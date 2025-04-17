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

// #include <linux/rhashtable.h>

// struct arp_entry {
//     struct rhash_head node;
//     __be32 ip;
//     unsigned char mac[ETH_ALEN];
// };

// static struct rhashtable arp_table;

// static const struct rhashtable_params arp_params = {
//     .key_offset = offsetof(struct arp_entry, ip),
//     .key_len = sizeof(__be32),
//     .head_offset = offsetof(struct arp_entry, node),
//     .automatic_shrinking = true,
// };


/* 최대 SPI 버퍼 크기 제한 */
#define SPI_MAX_BUF_SIZE    1024
#define SI917_IRQ_GPIO      50  /* 실제 IRQ 핀 번호로 수정 필요 */ 
#define SI917_SPI_MARGINE   16

struct spi_net_priv {
    struct net_device *net_dev;
    struct spi_device *spi_dev;
    struct work_struct rx_work;
    struct workqueue_struct *rwq;
    struct work_struct tx_work;
    struct workqueue_struct *twq;
    unsigned char *tx_buffer;
    unsigned char *tx_wait_data[10];
    unsigned char tx_wait_cnt;
    unsigned char tx_read_cnt;
    unsigned char tx_write_cnt;

    unsigned char *rx_buffer;
    unsigned char rx_wait_cnt;
    int irq;
    // size_t tx_len;


    struct mutex        spi_lock;
    // struct mutex        tx_lock;
    struct mutex        net_lock;
    // struct mutex        rx_lock;
};

bool irq_flag;
bool irq_end;

// void add_arp_map(__be32 ip, unsigned char *mac) {
//     struct arp_entry *entry;

//     entry = kmalloc(sizeof(*entry), GFP_KERNEL);
//     if (!entry)
//         return;

//     entry->ip = ip;
//     memcpy(entry->mac, mac, ETH_ALEN);

//     if (rhashtable_insert_fast(&arp_table, &entry->node, arp_params))
//         pr_err("Failed to insert ARP entry\n");
//     else
//         pr_info("Added ARP entry: IP=%pI4, MAC=%pM\n", &ip, mac);
// }


// void handle_arp_packet(struct net_device *dev, struct sk_buff *skb) {
//     struct arphdr *arp = arp_hdr(skb);
//     unsigned char *arp_ptr = (unsigned char *)(arp + 1);
//     __be32 sender_ip;
//     unsigned char sender_mac[ETH_ALEN];

//     if (arp->ar_op != htons(ARPOP_REQUEST) && arp->ar_op != htons(ARPOP_REPLY))
//         return;

//     memcpy(sender_mac, arp_ptr, ETH_ALEN);
//     arp_ptr += ETH_ALEN;
//     memcpy(&sender_ip, arp_ptr, 4);

//     /* MAP에 저장 */
//     add_arp_map(sender_ip, sender_mac);
// }


/* 수신 데이터 처리 함수 */
static void spi_net_receive_packet(struct spi_net_priv *priv) {
    struct net_device *dev = priv->net_dev;
    struct sk_buff *skb;
    unsigned char *data;
    int len;
    // int seq;
    // int i;

    // if (priv->rx_buffer[SI917_SPI_MARGINE+13] != 0x00) {
    //     // pr_info("ARP : 0x%02x 0x%02x 0x%02x\n", priv->rx_buffer[SI917_SPI_MARGINE+12] , priv->rx_buffer[SI917_SPI_MARGINE+13], priv->rx_buffer[SI917_SPI_MARGINE+41]);
    //     return;
    // }
    // else {
        // seq = (priv->rx_buffer[SI917_SPI_MARGINE+40]*256) + priv->rx_buffer[SI917_SPI_MARGINE+41];
        // pr_info("IP4 : 0x%02x 0x%02x %d 0x%02x\n", priv->rx_buffer[SI917_SPI_MARGINE+12] , priv->rx_buffer[SI917_SPI_MARGINE+13], seq, priv->rx_buffer[SI917_SPI_MARGINE+41]);
    // }

    /* 패킷 길이 디코딩 - 프로토콜에 맞게 조정 필요 */
    len = priv->rx_buffer[SI917_SPI_MARGINE+16];
    len *= 256;
    len += priv->rx_buffer[SI917_SPI_MARGINE+17];
    len += 14;
    // pr_info("RX LEN:%d\n", len);

    /* 버퍼 크기 및 MTU 제한 확인 */
    if (len > SPI_MAX_BUF_SIZE-SI917_SPI_MARGINE || len > dev->mtu) {
        dev->stats.rx_dropped++;
        return;
    }
    
    skb = dev_alloc_skb(len + NET_IP_ALIGN);
    if (!skb) {
        dev->stats.rx_dropped++;
        return;
    }

    // if (eth_hdr(skb)->h_proto == htons(ETH_P_ARP)) {
    //    pr_info("Received ARP packet\n");
    //    handle_arp_packet(dev, skb);
    //    return;
    // }
    
    skb_reserve(skb, NET_IP_ALIGN);
    data = skb_put(skb, len);
    memcpy(data, &priv->rx_buffer[SI917_SPI_MARGINE], len);
    memset(priv->rx_buffer, 0, SPI_MAX_BUF_SIZE-SI917_SPI_MARGINE);
    
    /* 네트워크 메타데이터 설정 */
    skb->dev = dev;
    skb->protocol = eth_type_trans(skb, dev);
    skb->ip_summed = CHECKSUM_NONE;
    
    /* 통계 업데이트 */
    dev->stats.rx_packets++;
    dev->stats.rx_bytes += len;
    
    /* 네트워크 스택으로 패킷 전달 */
    netif_rx(skb);
}

/* 수신 데이터 처리 함수 */
static void spi_net_rx_work(struct work_struct *work) {
    struct spi_net_priv *priv = container_of(work, struct spi_net_priv, rx_work);
    // struct net_device *dev = priv->net_dev;
    // struct spi_device *spi = priv->spi_dev;
    // struct sk_buff *skb;
    // unsigned char *data;
    // int len;
    int ret;
    // int i;

    // usleep_range(5000, 6000);

    ret = gpio_get_value(SI917_IRQ_GPIO);
    if (ret < 0) {
        pr_err("Failed GPIO %d Value.\n", SI917_IRQ_GPIO);
        return;
    }
    else if (ret == 1){
        usleep_range(200,300);
    }

    priv->rx_wait_cnt++;
    // pr_info("RX IRQ!!:%d\n", priv->tx_wait_cnt);

    // if (priv->tx_wait_cnt == 0) {
    //     if (priv->tx_wait_cnt < 10 && priv->tx_write_cnt < 10) {
    //         memset(priv->tx_wait_data[priv->tx_wait_cnt], 0x00, SPI_MAX_BUF_SIZE);
    //         priv->tx_wait_cnt++;
    //         priv->tx_write_cnt++;
    //         // pr_info("wait:%d write:%d\n", priv->tx_wait_cnt, priv->tx_write_cnt);
    //     }
    //     else {
    //         // pr_err("TX Wait Cnt Over!!\n");
    //         return;
    //     }
    //     queue_work(priv->twq, &priv->tx_work);
    // }
    // mutex_lock(&priv->spi_lock);
    // /* 최대 버퍼 크기만큼 데이터 읽기 */
    // spi_read(spi, priv->rx_buffer, SPI_MAX_BUF_SIZE);
    // usleep_range(200, 250);
    // mutex_unlock(&priv->spi_lock);

    // mutex_lock(&priv->net_lock);
    // spi_net_receive_packet(priv);
    // mutex_unlock(&priv->net_lock);
}

extern int spi_sync(struct spi_device *spi, struct spi_message *message);


static void spi_net_xmit_work(struct work_struct *work) {
    struct spi_net_priv *priv = container_of(work, struct spi_net_priv, tx_work);
    struct spi_device *spi = priv->spi_dev;
    struct spi_transfer t = {0};
       
    struct spi_message  m;
    int ret;
    // bool recv_flag = true;

    // int i;


    
    ret = gpio_get_value(SI917_IRQ_GPIO);
    if (ret < 0) {
        pr_err("Failed GPIO %d Value.\n", SI917_IRQ_GPIO);
        return;
    }
    // else if (ret == 0) {
    //     if (irq_flag)  {
    //         irq_flag = false;
    //         recv_flag = true;
    //     }
    // }
    else if (ret == 1) {
        usleep_range(80,100);
    }

    if (priv->tx_wait_cnt == 0) return;

    mutex_lock(&priv->spi_lock);
    t.tx_buf     = priv->tx_wait_data[priv->tx_read_cnt],
    t.rx_buf     = priv->rx_buffer,
    t.len        = SPI_MAX_BUF_SIZE,
    
    spi_message_init(&m);
    spi_message_add_tail(&t, &m);
    ret = spi_sync(spi, &m);
    if (ret < 0) {
        pr_err("SPI async write failed\n");
    }
    usleep_range(200, 250);
    mutex_unlock(&priv->spi_lock);

    priv->tx_wait_cnt--;
    priv->tx_read_cnt++;

    if(priv->tx_write_cnt == priv->tx_read_cnt) {
        priv->tx_wait_cnt = 0;
        priv->tx_read_cnt = 0;
        priv->tx_write_cnt = 0;
    }

    // if (!recv_flag) return;
    if (priv->rx_wait_cnt == 0) {
        
        return;
    }
    else priv->rx_wait_cnt--;

    mutex_lock(&priv->net_lock);
    // if (priv->rx_buffer[0] != 0) {
        spi_net_receive_packet(priv);
    // }
    mutex_unlock(&priv->net_lock);
}

/* IRQ 핸들러 */
static irqreturn_t spi_net_irq_handler(int irq, void *dev_id) {
    struct spi_net_priv *priv = dev_id;
    
    irq_flag = true;
    irq_end = true;
    /* 워크큐에 RX 작업 예약 */
    queue_work(priv->rwq, &priv->rx_work);
    
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

    // int len;

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
    
    // mutex_lock(&priv->tx_lock);
    memset(priv->tx_buffer, 0x00, SPI_MAX_BUF_SIZE);
    memcpy(priv->tx_buffer, skb->data, skb->len);

    if (priv->tx_wait_cnt < 10 && priv->tx_write_cnt < 10) {
        memset(priv->tx_wait_data[priv->tx_wait_cnt], 0x00, SPI_MAX_BUF_SIZE);
        memcpy(priv->tx_wait_data[priv->tx_wait_cnt], priv->tx_buffer, skb->len);
        priv->tx_wait_cnt++;
        priv->tx_write_cnt++;
        // pr_info("wait:%d write:%d\n", priv->tx_wait_cnt, priv->tx_write_cnt);
    }
    else {
        // pr_err("TX Wait Cnt Over!!\n");
        return 0;
    }

    queue_work(priv->twq, &priv->tx_work);
    
    dev->stats.tx_packets++;
    dev->stats.tx_bytes += skb->len;
    
    dev_kfree_skb(skb);

    return NETDEV_TX_OK;
}

static int spi_net_open(struct net_device *dev) {
    struct spi_net_priv *priv = netdev_priv(dev);
    int ret;

    if (!gpio_is_valid(SI917_IRQ_GPIO)) {
        pr_err("Invalid GPIO %d\n", SI917_IRQ_GPIO);
        return -ENODEV;
    }

    /* GPIO IRQ 설정 */
    ret = gpio_request(SI917_IRQ_GPIO, "spi_net_irq");
    if (ret) {
        pr_err("Failed to request GPIO %d\n", SI917_IRQ_GPIO);
        return ret;
    }

    ret = gpio_direction_input(SI917_IRQ_GPIO);
    if (ret) {
        pr_err("Failed to set GPIO %d as input\n", SI917_IRQ_GPIO);
        gpio_free(SI917_IRQ_GPIO);
        return ret;
    }

    priv->irq = gpio_to_irq(SI917_IRQ_GPIO);

    /* 워크큐 초기화 */
    INIT_WORK(&priv->rx_work, spi_net_rx_work);
    priv->rwq = create_singlethread_workqueue("spi_net_rx_wq");
    if (!priv->rwq) {
        free_irq(priv->irq, priv);
        gpio_free(SI917_IRQ_GPIO);
        return -ENOMEM;
    }

    INIT_WORK(&priv->tx_work, spi_net_xmit_work);
    priv->twq = create_workqueue("spi_net_tx_wq");
    if (!priv->rwq) {
        free_irq(priv->irq, priv);
        gpio_free(SI917_IRQ_GPIO);
        return -ENOMEM;
    }

  /* 인터럽트 핸들러 등록 */
    ret = request_irq(priv->irq, spi_net_irq_handler, 
                     IRQF_TRIGGER_RISING | IRQF_DISABLED, "spi_net_irq", priv);
    if (ret) {
        pr_err("Failed to request IRQ %d\n", priv->irq);
        gpio_free(SI917_IRQ_GPIO);
        return ret;
    }

    irq_flag = false;

    netif_start_queue(dev);
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

// static void set_mac_address(struct net_device *dev) {
//     // 원하는 MAC 주소 설정 (예: 02:AB:CD:EF:12:34)
//     unsigned char mac_addr[ETH_ALEN] = {0xEC, 0xF6, 0x4C, 0xA0, 0x15, 0xEC};

//     memcpy(dev->dev_addr, mac_addr, ETH_ALEN);
// }

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
    // mutex_init(&priv->tx_lock);
    // mutex_init(&priv->rx_lock);
    
    /* 버퍼 할당 */
    priv->tx_buffer = kmalloc(SPI_MAX_BUF_SIZE, GFP_KERNEL);
    if (!priv->tx_buffer) {
        free_netdev(net_dev);
        return -ENOMEM;
    }
    
    priv->rx_buffer = kmalloc(SPI_MAX_BUF_SIZE, GFP_KERNEL);
    if (!priv->rx_buffer) {
        kfree(priv->tx_buffer);
        free_netdev(net_dev);
        return -ENOMEM;
    }

    for(i=0;i<10;i++) {
        priv->tx_wait_data[i] = kmalloc(SPI_MAX_BUF_SIZE, GFP_KERNEL);
        if (!priv->tx_wait_data[i]) {
            kfree(priv->tx_buffer);
            kfree(priv->rx_buffer);
            free_netdev(net_dev);
            return -ENOMEM;
        }
    }

    priv->tx_wait_cnt = 0;
    priv->tx_read_cnt = 0;
    priv->tx_write_cnt = 0;

    net_dev->netdev_ops = &spi_netdev_ops;
    net_dev->flags &= ~IFF_NOARP;
    // net_dev->features |= NETIF_F_HW_CSUM;
    // net_dev->addr_assign_type = NET_ADDR_SET;

    // set_mac_address(net_dev);
    
    /* MAC 주소 설정 */
    // random_ether_addr(net_dev->dev_addr);
    
    if (register_netdev(net_dev)) {
        kfree(priv->rx_buffer);
        kfree(priv->tx_buffer);
        free_netdev(net_dev);
        return -EIO;
    }
    

    spi_set_drvdata(spi, priv);
    pr_info("SPI network device registered (buffer size: %d bytes)\n", SPI_MAX_BUF_SIZE);
    return 0;
}

static int spi_net_remove(struct spi_device *spi) {
    struct spi_net_priv *priv = spi_get_drvdata(spi);
    
    unregister_netdev(priv->net_dev);
    kfree(priv->rx_buffer);
    kfree(priv->tx_buffer);
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