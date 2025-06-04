#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/spi/spi.h>
#include <linux/etherdevice.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/gpio.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/irq.h>
#include <linux/init.h>
#include <linux/if_arp.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/inetdevice.h>
#include <linux/sched.h>

#include <net/neighbour.h>
#include <net/arp.h>

#include <linux/list.h>
#include <linux/spinlock.h>

/* 최대 SPI 버퍼 크기 제한 */
#define SPI_MAX_BUF_SIZE    1024
#define SPI_BUF_NUM         10240
#define SI917_IRQ_GPIO      50  /* RX IRQ GPIO */ 
#define SI917_WAIT_GPIO     51  /* SPI Start GPIO */
#define SI917_SPI_MARGINE   16

struct spi_net_priv {
    struct net_device *net_dev;
    struct spi_device *spi_dev;

    struct work_struct rx_work;
    struct workqueue_struct *rwq;
    struct work_struct tx_work;
    struct workqueue_struct *twq;

    struct task_struct *spi_thread;
    wait_queue_head_t spi_wait;
    bool spi_pending;

    unsigned char *tx_buf[SPI_BUF_NUM];
    int w_cnt;
    int r_cnt;

    unsigned char *rx_buffer;
    int irq;

    int rx_cnt;

    struct mutex        spi_lock;
    struct mutex        net_lock;
};

bool gw_art_set = false;

unsigned char *tx_test;

// static void spi_net_process_arp(struct net_device *dev, const unsigned char *data, int len) {
//     struct arphdr *arp_hdr;
//     unsigned char *arp_ptr;
//     __be32 sip;
//     unsigned char *sha;

//     if (len < sizeof(struct arphdr) + 2 * ETH_ALEN + 2 * sizeof(__be32)) {
//         pr_info("ARP packet too short\n");
//         return;
//     }

//     arp_hdr = (struct arphdr *)data;
//     if (arp_hdr->ar_op != htons(ARPOP_REPLY) && arp_hdr->ar_op != htons(ARPOP_REQUEST)){
//         pr_info("hdr:%d op:%d\n", arp_hdr->ar_op, arp_hdr->ar_op);
//         return;
//     }

//     arp_ptr = (unsigned char *)(arp_hdr + 1);
//     sha = arp_ptr;
//     sip = *(__be32 *)(arp_ptr + ETH_ALEN);

//     neigh_update(neigh_lookup(&arp_tbl, &sip, dev), sha, NUD_REACHABLE,
//                  NEIGH_UPDATE_F_OVERRIDE | NEIGH_UPDATE_F_ADMIN);
//     pr_info("ARP cached: IP=%pI4, MAC=%pM\n", &sip, sha);
// }

struct mac_change_record {
    __be32 ip;
    bool changed;
    struct list_head list;
};

static LIST_HEAD(mac_change_list);
static DEFINE_SPINLOCK(mac_list_lock);

static bool has_mac_changed(__be32 ip) {
    struct mac_change_record *rec;
    bool found = false;

    spin_lock(&mac_list_lock);
    list_for_each_entry(rec, &mac_change_list, list) {
        if (rec->ip == ip) {
            found = rec->changed;
            break;
        }
    }
    spin_unlock(&mac_list_lock);
    return found;
}

static void mark_mac_changed(__be32 ip) {
    struct mac_change_record *rec;
    bool exists = false;

    spin_lock(&mac_list_lock);
    list_for_each_entry(rec, &mac_change_list, list) {
        if (rec->ip == ip) {
            rec->changed = true;
            exists = true;
            break;
        }
    }

    if (!exists) {
        rec = kzalloc(sizeof(*rec), GFP_ATOMIC);
        if (rec) {
            rec->ip = ip;
            rec->changed = true;
            list_add(&rec->list, &mac_change_list);
        }
    }
    spin_unlock(&mac_list_lock);
}

static void spi_net_process_arp(struct net_device *dev, const unsigned char *data, int len) {
    struct arphdr *arp_hdr;
    unsigned char *arp_ptr;
    __be32 sip;
    unsigned char *sha;
    struct neighbour *n;

    if (len < sizeof(struct arphdr) + 2 * ETH_ALEN + 2 * sizeof(__be32)) {
        pr_info("ARP packet too short\n");
        return;
    }

    arp_hdr = (struct arphdr *)data;
    if (arp_hdr->ar_op != htons(ARPOP_REPLY) && arp_hdr->ar_op != htons(ARPOP_REQUEST)) {
        pr_info("Invalid ARP op: %d\n", ntohs(arp_hdr->ar_op));
        return;
    }

    arp_ptr = (unsigned char *)(arp_hdr + 1);
    sha = arp_ptr;
    sip = *(__be32 *)(arp_ptr + ETH_ALEN);

    n = neigh_lookup(&arp_tbl, &sip, dev);
    if (!n) {
        // 신규 등록
        n = neigh_create(&arp_tbl, &sip, dev);
        if (IS_ERR(n)) {
            pr_info("Failed to create neighbor entry\n");
            return;
        }

        neigh_update(n, sha, NUD_PERMANENT,
                     NEIGH_UPDATE_F_OVERRIDE | NEIGH_UPDATE_F_ADMIN);
        pr_info("ARP new entry: IP=%pI4, MAC=%pM\n", &sip, sha);
        neigh_release(n);
        return;
    }

    // 이미 등록된 경우
    if (ether_addr_equal(n->ha, sha)) {
        // pr_info("ARP unchanged: IP=%pI4, MAC=%pM\n", &sip, sha);
    } else {
        if (!has_mac_changed(sip)) {
            neigh_update(n, sha, NUD_PERMANENT,
                         NEIGH_UPDATE_F_OVERRIDE | NEIGH_UPDATE_F_ADMIN);
            mark_mac_changed(sip);
            pr_info("ARP 1st change allowed: IP=%pI4, New MAC=%pM\n", &sip, sha);
        } else {
            // pr_warn("ARP change blocked: IP=%pI4 already changed once. Current MAC=%pM, New MAC=%pM\n",
                    // &sip, n->ha, sha);
        }
    }

    neigh_release(n);
}
/* 수신 데이터 처리 함수 */
// static void spi_net_receive_packet(struct spi_net_priv *priv) {
//     struct net_device *dev = priv->net_dev;
//     struct sk_buff *skb;
//     unsigned char *data;
//     int len;

//     /* 패킷 길이 디코딩 - 프로토콜에 맞게 조정 필요 */
//     if (priv->rx_buffer[SI917_SPI_MARGINE+12] == 0x08 && priv->rx_buffer[SI917_SPI_MARGINE+13] == 0x00) {
//         len = priv->rx_buffer[SI917_SPI_MARGINE+16];
//         len *= 256;
//         len += priv->rx_buffer[SI917_SPI_MARGINE+17];
//         len += 14;
//     }

//     // pr_info("recv len : %d\n", len);
    
//     // for(i=0; i<len+16+14; i++) {
//     //     pr_info("0x%02x ", priv->rx_buffer[i]);
//     // }
//     // pr_info("\n");

//     if (priv->rx_buffer[SI917_SPI_MARGINE+12] == 0x08 && priv->rx_buffer[SI917_SPI_MARGINE+13] == 0x06) {
//         len = 28;
//         skb = dev_alloc_skb(len + NET_IP_ALIGN);
//         if (!skb) {
//             dev->stats.rx_dropped++;
//             return;
//         }

//         skb_reserve(skb, NET_IP_ALIGN);
//         data = skb_put(skb, len);

//         memcpy(data, &priv->rx_buffer[SI917_SPI_MARGINE+14], len);
//         memset(priv->rx_buffer, 0, SPI_MAX_BUF_SIZE-SI917_SPI_MARGINE);

//         spi_net_process_arp(dev, data, len);
//         // pr_info("arp set\n");

//         return;
//     }
 
//     /* 버퍼 크기 및 MTU 제한 확인 */
//     if (len > SPI_MAX_BUF_SIZE-SI917_SPI_MARGINE || len > dev->mtu) {
//         dev->stats.rx_dropped++;
//         return;
//     }
    
//     skb = dev_alloc_skb(len + NET_IP_ALIGN);
//     if (!skb) {
//         dev->stats.rx_dropped++;
//         return;
//     }

//     skb_reserve(skb, NET_IP_ALIGN);
//     data = skb_put(skb, len);
//     memcpy(data, &priv->rx_buffer[SI917_SPI_MARGINE], len);
//     memset(priv->rx_buffer, 0, SPI_MAX_BUF_SIZE-SI917_SPI_MARGINE);
    
//     /* 네트워크 메타데이터 설정 */
//     skb->dev = dev;
//     skb->protocol = eth_type_trans(skb, dev);
//     skb->ip_summed = CHECKSUM_NONE;
    
//     if (skb->protocol == htons(ETH_P_ARP)) {
//         spi_net_process_arp(dev, data, len);
//         // pr_info("arp set\n");
//     }

//     /* 통계 업데이트 */
//     dev->stats.rx_packets++;
//     dev->stats.rx_bytes += len;
    
//     /* 네트워크 스택으로 패킷 전달 */
//     netif_rx(skb);
// }


#define MAX_PACKET_SIZE     2048

static unsigned char rx_partial_buf[MAX_PACKET_SIZE];
static int rx_partial_len = 0;
static int rx_large_len = 0;

static void spi_net_receive_packet2(struct spi_net_priv *priv) {
    struct net_device *dev = priv->net_dev;
    struct sk_buff *skb;
    unsigned char *data;
    int len = 0;

    // int i = 0;

    /* 프로토콜 확인 및 길이 파싱 */
    if (priv->rx_buffer[SI917_SPI_MARGINE+12] == 0x08 &&
        priv->rx_buffer[SI917_SPI_MARGINE+13] == 0x00) {
        len = priv->rx_buffer[SI917_SPI_MARGINE+16] << 8 |
              priv->rx_buffer[SI917_SPI_MARGINE+17];
        len += 14;  // Ethernet header
        // pr_info("IPv4:%d", len);        
    }
    // else {
        // pr_info("type:0x%02x 0x%02x", priv->rx_buffer[SI917_SPI_MARGINE+12], priv->rx_buffer[SI917_SPI_MARGINE+13]);        
    // }


    /* ARP 패킷 */
    if (priv->rx_buffer[SI917_SPI_MARGINE+12] == 0x08 &&
        priv->rx_buffer[SI917_SPI_MARGINE+13] == 0x06) {
        len = 28;
        skb = dev_alloc_skb(len + NET_IP_ALIGN);
        if (!skb) {
            dev->stats.rx_dropped++;
            return;
        }

        skb_reserve(skb, NET_IP_ALIGN);
        data = skb_put(skb, len);

        memcpy(data, &priv->rx_buffer[SI917_SPI_MARGINE+14], len);
        memset(priv->rx_buffer, 0, SPI_MAX_BUF_SIZE - SI917_SPI_MARGINE);

        spi_net_process_arp(dev, data, len);
        return;
    }

    // if (priv->rx_buffer[SI917_SPI_MARGINE+14+20+8+4] == 0x21 &&
    //     priv->rx_buffer[SI917_SPI_MARGINE+14+20+8+5] == 0x12 &&
    //     priv->rx_buffer[SI917_SPI_MARGINE+14+20+8+6] == 0xa4 &&
    //     priv->rx_buffer[SI917_SPI_MARGINE+14+20+8+7] == 0x42) {
    //     pr_info("****************************STUN RECV!!******************************\n");
    //     for(i=0;i<len;i++) {
    //         pr_info("0x%02x ", priv->rx_buffer[SI917_SPI_MARGINE+i]);
    //     }
    //     pr_info("\n");
    // }

    // pr_info("rx:%d\n", len);
    /* 조각 수신 처리 */
    if (len > SPI_MAX_BUF_SIZE - SI917_SPI_MARGINE || rx_partial_len != 0) {
        if (rx_partial_len == 0) {
            // pr_info("lpckt:%d\n",len);
            // 첫 번째 조각 저장
            memcpy(rx_partial_buf, &priv->rx_buffer[SI917_SPI_MARGINE], SPI_MAX_BUF_SIZE - SI917_SPI_MARGINE);
            rx_partial_len = SPI_MAX_BUF_SIZE - SI917_SPI_MARGINE;
            rx_large_len = len;
        } else {
            
            // 두 번째 조각 수신 및 결합
            int second_part_len = rx_large_len - rx_partial_len;
            if (rx_partial_len + second_part_len > MAX_PACKET_SIZE) {
                dev->stats.rx_dropped++;
                rx_partial_len = 0;
                return;
            }
            // pr_info("large pck state2 : %d\n", second_part_len);
            memcpy(rx_partial_buf + rx_partial_len, &priv->rx_buffer[SI917_SPI_MARGINE], second_part_len);
            rx_partial_len += second_part_len;

            // pr_info("0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n", rx_partial_buf[rx_partial_len-5], rx_partial_buf[rx_partial_len-4], rx_partial_buf[rx_partial_len-3], rx_partial_buf[rx_partial_len-2], rx_partial_buf[rx_partial_len-1]);

            skb = dev_alloc_skb(rx_partial_len + NET_IP_ALIGN);
            if (!skb) {
                dev->stats.rx_dropped++;
                rx_partial_len = 0;
                return;
            }

            skb_reserve(skb, NET_IP_ALIGN);
            data = skb_put(skb, rx_partial_len);
            memcpy(data, rx_partial_buf, rx_partial_len);
            memset(rx_partial_buf, 0, MAX_PACKET_SIZE);
            rx_partial_len = 0;

            skb->dev = dev;
            skb->protocol = eth_type_trans(skb, dev);
            skb->ip_summed = CHECKSUM_NONE;

            if (skb->protocol == htons(ETH_P_ARP)) {
                spi_net_process_arp(dev, data, rx_partial_len);
            }

            dev->stats.rx_packets++;
            dev->stats.rx_bytes += rx_partial_len;

            netif_rx(skb);
        }

        memset(priv->rx_buffer, 0, SPI_MAX_BUF_SIZE - SI917_SPI_MARGINE);
        return;
    }

    /* 일반 처리 */
    if (len !=0) {
        skb = dev_alloc_skb(len + NET_IP_ALIGN);
        if (!skb) {
            dev->stats.rx_dropped++;
            return;
        }

        skb_reserve(skb, NET_IP_ALIGN);
        data = skb_put(skb, len);
        memcpy(data, &priv->rx_buffer[SI917_SPI_MARGINE], len);
        memset(priv->rx_buffer, 0, SPI_MAX_BUF_SIZE - SI917_SPI_MARGINE);

        skb->dev = dev;
        skb->protocol = eth_type_trans(skb, dev);
        skb->ip_summed = CHECKSUM_NONE;

        if (skb->protocol == htons(ETH_P_ARP)) {
            spi_net_process_arp(dev, data, len);
        }

        dev->stats.rx_packets++;
        dev->stats.rx_bytes += len;
        netif_rx(skb);
    }
}


extern int spi_sync(struct spi_device *spi, struct spi_message *message);

static int spi_thread_fn(void *data) {
    struct spi_net_priv *priv = data;
    struct spi_transfer t = {0};
    struct spi_message m;
    int ret, wait;
    unsigned char *spi_buf = kmalloc(SPI_MAX_BUF_SIZE, GFP_KERNEL);

    // pr_info("priv:%p\n", priv);

    while (!kthread_should_stop()) {
        wait_event_interruptible(priv->spi_wait, priv->spi_pending || kthread_should_stop());
        if (kthread_should_stop())
            break;

        priv->spi_pending = false;

        while (priv->r_cnt < priv->w_cnt) {
            wait = ret = 1;
            while(wait || ret) {
                wait = gpio_get_value(SI917_WAIT_GPIO);
                ret = gpio_get_value(SI917_IRQ_GPIO);
                // if (wait) usleep_range(300, 500);
            }

            memcpy(spi_buf, priv->tx_buf[priv->r_cnt], SPI_MAX_BUF_SIZE);
            priv->r_cnt++;

            if (priv->r_cnt >= priv->w_cnt) priv->r_cnt = priv->w_cnt = 0;

            mutex_lock(&priv->spi_lock);
            memset(&t, 0, sizeof(t));
            // t.tx_buf = priv->tx_buf[priv->r_cnt];
            t.tx_buf = spi_buf;
            t.rx_buf = priv->rx_buffer;
            t.len = SPI_MAX_BUF_SIZE;

            spi_message_init(&m);
            spi_message_add_tail(&t, &m);

            ret = spi_sync(priv->spi_dev, &m);
            mutex_unlock(&priv->spi_lock);

            if (ret < 0)
                pr_err("SPI TX failed\n");

            // priv->r_cnt++;

            // pr_info("r%d w%d rx:%d\n", priv->r_cnt, priv->w_cnt, priv->rx_cnt);
            if (priv->rx_cnt > 0) {
                mutex_lock(&priv->net_lock);
                spi_net_receive_packet2(priv);
                mutex_unlock(&priv->net_lock);
                priv->rx_cnt--;
            }

            usleep_range(300, 500);
        }

        priv->r_cnt = priv->w_cnt = 0;

        if (priv->r_cnt > SPI_BUF_NUM || priv->w_cnt > SPI_BUF_NUM) {
            priv->r_cnt = priv->w_cnt = 0;
        }
    }
    return 0;
}

/* IRQ 핸들러 */
static irqreturn_t spi_net_irq_handler(int irq, void *dev_id) {
    struct spi_net_priv *priv = dev_id;
    int data_cnt;

    priv->rx_cnt++;
    data_cnt = priv->w_cnt - priv->r_cnt;

    if (data_cnt > 1) return IRQ_HANDLED;
 
    if (priv->w_cnt < SPI_BUF_NUM-1) {
        memset(priv->tx_buf[priv->w_cnt], 0, SPI_MAX_BUF_SIZE);
        priv->w_cnt++;
    }

    priv->spi_pending = true;
    wake_up_interruptible(&priv->spi_wait);

    return IRQ_HANDLED;
}

static int spi_net_set_mac_address(struct net_device *dev, void *p) {
    struct sockaddr *addr = p;

    if (!is_valid_ether_addr(addr->sa_data))  // 유효한 MAC 주소인지 확인
        return -EADDRNOTAVAIL;

    memcpy(dev->dev_addr, addr->sa_data, ETH_ALEN);
    return 0;
}

static netdev_tx_t spi_net_xmit(struct sk_buff *skb, struct net_device *dev) {
    struct spi_net_priv *priv = netdev_priv(dev);
    struct spi_device *spi = priv->spi_dev;
    int data_cnt = 0;
    // int i;

    if (!spi) {
        pr_err("SPI device not initialized\n");
        dev_kfree_skb(skb);
        return NETDEV_TX_OK;
    }

    /* 버퍼 크기 제한 확인 */
    if (skb->len > SPI_MAX_BUF_SIZE) {
        pr_err("Packet too large (%d bytes), max allowed is %d bytes\n", 
               skb->len, SPI_MAX_BUF_SIZE);
        dev->stats.tx_dropped++;
        dev_kfree_skb(skb);
        return NETDEV_TX_OK;
    }

    /* 기본적인 예외 처리 */
    if (skb->len < 0 || !skb->data) {
        dev->stats.tx_errors++;
        dev_kfree_skb(skb);
        return NETDEV_TX_OK;
    }

    /* TX 버퍼에 데이터 복사 */
    data_cnt = priv->w_cnt - priv->r_cnt;
    if (data_cnt < (SPI_BUF_NUM-1) && priv->w_cnt < (SPI_BUF_NUM-1)) {
        memset(priv->tx_buf[priv->w_cnt], 0, SPI_MAX_BUF_SIZE);
        memcpy(priv->tx_buf[priv->w_cnt], skb->data, skb->len);

        // queue_work(priv->twq, &priv->tx_work);
        priv->w_cnt++;

        priv->spi_pending = true;
        wake_up_interruptible(&priv->spi_wait);

        // pr_info("w_cnt :%d r_cnt:%d\n", priv->w_cnt, priv->r_cnt);
        
        dev->stats.tx_packets++;
        dev->stats.tx_bytes += skb->len;
        // pr_info("tx:%d\n", skb->len);
    }
    else {
        priv->spi_pending = true;
        wake_up_interruptible(&priv->spi_wait);

        pr_info("Data full r%d w%d\n", priv->r_cnt, priv->w_cnt);
    }
    
    dev_kfree_skb(skb);

    return NETDEV_TX_OK;
}

static int spi_net_open(struct net_device *dev) {
    struct sched_param param;
    struct spi_net_priv *priv = netdev_priv(dev);
    int ret, i;

    /* Set Rx IRQ GPIO */
    if (!gpio_is_valid(SI917_IRQ_GPIO)) {
        pr_err("Invalid GPIO %d\n", SI917_IRQ_GPIO);
        return -ENODEV;
    }
    ret = gpio_direction_input(SI917_IRQ_GPIO);
    if (ret) {
        pr_err("Failed to set GPIO %d as input\n", SI917_IRQ_GPIO);
        gpio_free(SI917_IRQ_GPIO);
        return ret;
    }
    ret = gpio_request(SI917_IRQ_GPIO, "spi_net_irq");
    if (ret) {
        pr_err("Failed to request GPIO %d\n", SI917_IRQ_GPIO);
        return ret;
    }
    priv->irq = gpio_to_irq(SI917_IRQ_GPIO);

    /* Set SPI Start Enable GPIO */
    if (!gpio_is_valid(SI917_WAIT_GPIO)) {
        pr_err("Invalid GPIO %d\n", SI917_WAIT_GPIO);
        return -ENODEV;
    }
    ret = gpio_direction_input(SI917_WAIT_GPIO);
    if (ret) {
        pr_err("Failed to set GPIO %d as input\n", SI917_WAIT_GPIO);
        gpio_free(SI917_WAIT_GPIO);
        return ret;
    }

    /* SPI Thread */
    init_waitqueue_head(&priv->spi_wait);
    priv->spi_pending = false;
    priv->spi_thread = kthread_run(spi_thread_fn, priv, "spi_thread");

    param.sched_priority = 80; // 1~99 (높을수록 우선순위 높음)
    if (sched_setscheduler(priv->spi_thread, SCHED_FIFO, &param) != 0) {
        pr_err("Failed to set scheduler policy\n");
    } else {
        pr_info("kthread scheduler set to SCHED_FIFO, priority 80\n");
    }

    /* 인터럽트 핸들러 등록 */
    ret = request_irq(priv->irq, spi_net_irq_handler, 
                     IRQF_TRIGGER_FALLING, "spi_net_irq", priv);
    if (ret) {
        pr_err("Failed to request IRQ %d\n", priv->irq);
        gpio_free(SI917_IRQ_GPIO);
        return ret;
    }

    /* Net Start */
    netif_start_queue(dev);

    /* Start Dummy Data */
    for (i=0; i<10; i++) {
        memset(priv->tx_buf[priv->w_cnt], 0, SPI_MAX_BUF_SIZE);
        priv->w_cnt++;
        // pr_info("Start Dummy Set!\n");
    }

    return 0;
}

static int spi_net_stop(struct net_device *dev) {
    struct spi_net_priv *priv = netdev_priv(dev);
    
    netif_stop_queue(dev);
    
    /* 인터럽트 해제 */
    if (priv->irq) {
        free_irq(priv->irq, priv);
        gpio_free(SI917_IRQ_GPIO);
    }
    
    /* 워크큐 해제 */
    if (priv->rwq) {
        cancel_work_sync(&priv->rx_work);
        destroy_workqueue(priv->rwq);
    }

    if (priv->twq) {
        cancel_work_sync(&priv->tx_work);
        destroy_workqueue(priv->twq);
    }
    
    return 0;
}

static const struct net_device_ops spi_netdev_ops = {
    .ndo_open = spi_net_open,
    .ndo_stop = spi_net_stop,
    .ndo_start_xmit = spi_net_xmit,
    .ndo_set_mac_address = spi_net_set_mac_address,  // MAC 주소 변경 지원
};

static int spi_net_probe(struct spi_device *spi) {
    struct net_device *net_dev;
    struct spi_net_priv *priv;
    int i;

    net_dev = alloc_etherdev(sizeof(struct spi_net_priv));
    if (!net_dev)
        return -ENOMEM;
    
    priv = netdev_priv(net_dev);
    priv->net_dev = net_dev;
    priv->spi_dev = spi;
    mutex_init(&priv->spi_lock);
    mutex_init(&priv->net_lock);
    
    priv->rx_buffer = kmalloc(SPI_MAX_BUF_SIZE, GFP_KERNEL);
    if (!priv->rx_buffer) {
        free_netdev(net_dev);
        return -ENOMEM;
    }

    net_dev->netdev_ops = &spi_netdev_ops;
    net_dev->flags &= ~IFF_NOARP;

    net_dev->mtu = 992;
    
    if (register_netdev(net_dev)) {
        kfree(priv->rx_buffer);
        free_netdev(net_dev);
        return -EIO;
    }
    
    for(i=0;i<SPI_BUF_NUM;i++) {
        priv->tx_buf[i] = kmalloc(SPI_MAX_BUF_SIZE, GFP_KERNEL);
        if (!priv->tx_buf[i]) { 
            free_netdev(net_dev);
            return -ENOMEM;
        }
    }

    tx_test = kmalloc(SPI_MAX_BUF_SIZE, GFP_KERNEL);
    for(i=0; i<SPI_MAX_BUF_SIZE; i++) {
        tx_test[i] = i%256;
    }

    priv->r_cnt = 0;
    priv->w_cnt = 0;
    priv->rx_cnt = 0;

    spi_set_drvdata(spi, priv);
    pr_info("SPI network device registered 20250512 (buffer size: %d bytes)\n", SPI_MAX_BUF_SIZE);
    return 0;
}


// static int spi_net_probe(struct spi_device *spi)
// {
//     struct net_device *net_dev;
//     struct spi_net_priv *priv;
//     int i;

//     // "wlan%d" 이름으로 인터페이스 생성
//     net_dev = alloc_netdev(sizeof(struct spi_net_priv), "wlan%d", NET_NAME_UNKNOWN, ether_setup);
//     if (!net_dev)
//         return -ENOMEM;

//     // 인터페이스 이름을 강제로 wlan0으로 설정
//     strlcpy(net_dev->name, "wlan0", IFNAMSIZ);

//     priv = netdev_priv(net_dev);
//     priv->net_dev = net_dev;
//     priv->spi_dev = spi;
//     mutex_init(&priv->spi_lock);
//     mutex_init(&priv->net_lock);

//     priv->rx_buffer = kmalloc(SPI_MAX_BUF_SIZE, GFP_KERNEL);
//     if (!priv->rx_buffer) {
//         free_netdev(net_dev);
//         return -ENOMEM;
//     }

//     net_dev->netdev_ops = &spi_netdev_ops;
//     net_dev->flags &= ~IFF_NOARP;
//     net_dev->mtu = 992;

//     if (register_netdev(net_dev)) {
//         kfree(priv->rx_buffer);
//         free_netdev(net_dev);
//         return -EIO;
//     }

//     for (i = 0; i < SPI_BUF_NUM; i++) {
//         priv->tx_buf[i] = kmalloc(SPI_MAX_BUF_SIZE, GFP_KERNEL);
//         if (!priv->tx_buf[i]) {
//             while (--i >= 0)
//                 kfree(priv->tx_buf[i]);
//             kfree(priv->rx_buffer);
//             unregister_netdev(net_dev);
//             free_netdev(net_dev);
//             return -ENOMEM;
//         }
//     }

//     tx_test = kmalloc(SPI_MAX_BUF_SIZE, GFP_KERNEL);
//     if (tx_test) {
//         for (i = 0; i < SPI_MAX_BUF_SIZE; i++) {
//             tx_test[i] = i % 256;
//         }
//     }

//     priv->r_cnt = 0;
//     priv->w_cnt = 0;
//     priv->rx_cnt = 0;

//     spi_set_drvdata(spi, priv);

//     pr_info("SPI network device registered as '%s' (buffer size: %d bytes)\n",
//             net_dev->name, SPI_MAX_BUF_SIZE);

//     return 0;
// }


static int spi_net_remove(struct spi_device *spi) {
    struct spi_net_priv *priv = spi_get_drvdata(spi);
    int i;
    
    unregister_netdev(priv->net_dev);
    kfree(priv->rx_buffer);
    for(i=0;i<SPI_BUF_NUM;i++) {
        kfree(priv->tx_buf[i]);
    }
    free_netdev(priv->net_dev);
    
    return 0;
}

static struct of_device_id spi_net_dt_ids[] = {
    { .compatible = "spi-net-device" },
    { }
};
MODULE_DEVICE_TABLE(of, spi_net_dt_ids);

static struct spi_driver spi_net_driver = {
    .driver = {
        .name = "spi_net",
        .of_match_table = spi_net_dt_ids,
    },
    .probe = spi_net_probe,
    .remove = spi_net_remove,
};

module_spi_driver(spi_net_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SPI Network Driver Developer");
MODULE_DESCRIPTION("SPI-based Network Device Driver with 1024 byte buffer limit");