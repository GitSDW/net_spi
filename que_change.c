#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/spi/spi.h>
#include <linux/etherdevice.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/gpio.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/inetdevice.h>
#include <linux/inet.h>
#include <net/neighbour.h>
#include <net/arp.h>

#define SPI_MAX_BUF_SIZE    1024
#define SPI_BUF_NUM         10240
#define SI917_IRQ_GPIO      50
#define SI917_WAIT_GPIO     51
#define SI917_SPI_MARGINE   16

#define TEST_CNT            5

static struct net_device *spi_net_dev;
static struct spi_device *spi_dev;

static struct task_struct *spi_thread;
static struct task_struct *rx_thread;

struct work_struct rx_work[TEST_CNT];
struct workqueue_struct *twq;

struct work_struct tx_work[TEST_CNT];
struct workqueue_struct *twq;

static DECLARE_WAIT_QUEUE_HEAD(spi_wait);
static bool spi_pending = false;

static unsigned char *tx_buf[SPI_BUF_NUM];
static unsigned char *rx_buffer;
static int r_cnt = 0, w_cnt = 0, rx_cnt = 0;

static DEFINE_MUTEX(spi_lock);
static DEFINE_MUTEX(net_lock);

static int irq;

/* 수신 데이터 처리 함수 */
static void spi_net_rx_work(struct work_struct *work) {
    static int wq_cnt = 0;
    pr_info("wrok queue : %d\n", wq_cnt);
    wq_cnt++;
    usleep_range(1000*1000, 1500*1000);
}

static void spi_net_send_arp_request(__be32 target_ip) {
    unsigned char *buf;
    struct ethhdr *eth;
    struct arphdr *arp;
    unsigned char *arp_ptr;
    __be32 src_ip = 0;
    unsigned char *src_mac;
    int len = 42;

    buf = kmalloc(SPI_MAX_BUF_SIZE, GFP_KERNEL);
    if (!buf)
        return;

    memset(buf, 0, SPI_MAX_BUF_SIZE);

    eth = (struct ethhdr *)buf;
    memset(eth->h_dest, 0xFF, ETH_ALEN);
    src_mac = spi_net_dev->dev_addr;
    memcpy(eth->h_source, src_mac, ETH_ALEN);
    eth->h_proto = htons(ETH_P_ARP);

    arp = (struct arphdr *)(buf + ETH_HLEN);
    arp->ar_hrd = htons(ARPHRD_ETHER);
    arp->ar_pro = htons(ETH_P_IP);
    arp->ar_hln = ETH_ALEN;
    arp->ar_pln = 4;
    arp->ar_op  = htons(ARPOP_REQUEST);

    arp_ptr = (unsigned char *)(arp + 1);
    memcpy(arp_ptr, src_mac, ETH_ALEN);
    arp_ptr += ETH_ALEN;

    if (spi_net_dev->ip_ptr && spi_net_dev->ip_ptr->ifa_list)
        src_ip = spi_net_dev->ip_ptr->ifa_list->ifa_address;
    memcpy(arp_ptr, &src_ip, 4);
    arp_ptr += 4;

    memset(arp_ptr, 0x00, ETH_ALEN);
    arp_ptr += ETH_ALEN;

    memcpy(arp_ptr, &target_ip, 4);

    if (w_cnt < SPI_BUF_NUM - 1) {
        memcpy(tx_buf[w_cnt], buf, len);
        w_cnt++;
        spi_pending = true;
        wake_up_interruptible(&spi_wait);
        pr_info("ARP request sent for IP: %pI4\n", &target_ip);
    }

    kfree(buf);
}

static void spi_net_receive_packet(void) {
    struct sk_buff *skb;
    unsigned char *data;
    int len;

    struct net_device *dev = spi_net_dev;

    len = rx_buffer[SI917_SPI_MARGINE+16] * 256 + rx_buffer[SI917_SPI_MARGINE+17] + 14;

    if (rx_buffer[SI917_SPI_MARGINE+12] == 0x08 && rx_buffer[SI917_SPI_MARGINE+13] == 0x06) {
        len = 28;
        skb = dev_alloc_skb(len + NET_IP_ALIGN);
        if (!skb) {
            dev->stats.rx_dropped++;
            return;
        }
        skb_reserve(skb, NET_IP_ALIGN);
        data = skb_put(skb, len);
        memcpy(data, &rx_buffer[SI917_SPI_MARGINE+14], len);
        memset(rx_buffer, 0, SPI_MAX_BUF_SIZE - SI917_SPI_MARGINE);
        netif_rx(skb);
        return;
    }

    if (len > SPI_MAX_BUF_SIZE - SI917_SPI_MARGINE || len > dev->mtu) {
        dev->stats.rx_dropped++;
        return;
    }

    skb = dev_alloc_skb(len + NET_IP_ALIGN);
    if (!skb) {
        dev->stats.rx_dropped++;
        return;
    }
    skb_reserve(skb, NET_IP_ALIGN);
    data = skb_put(skb, len);
    memcpy(data, &rx_buffer[SI917_SPI_MARGINE], len);
    memset(rx_buffer, 0, SPI_MAX_BUF_SIZE - SI917_SPI_MARGINE);

    skb->dev = dev;
    skb->protocol = eth_type_trans(skb, dev);
    skb->ip_summed = CHECKSUM_NONE;

    dev->stats.rx_packets++;
    dev->stats.rx_bytes += len;

    netif_rx(skb);
}

static int spi_thread_fn(void *data) {
    struct spi_transfer t = {0};
    struct spi_message m;
    int ret;
    // int wait_irq, wait_en;

    while (!kthread_should_stop()) {
        wait_event_interruptible(spi_wait, spi_pending || kthread_should_stop());
        if (kthread_should_stop())
            break;

        spi_pending = false;

        while (r_cnt < w_cnt) {

            // wait_en = wait_irq = 1;
            // while(wait_en || wait_irq) {
            //     wait_en = gpio_get_value(SI917_WAIT_GPIO);
            //     wait_irq = gpio_get_value(SI917_IRQ_GPIO);
            // }

            mutex_lock(&spi_lock);
            memset(&t, 0, sizeof(t));
            t.tx_buf = tx_buf[r_cnt];
            t.rx_buf = rx_buffer;
            t.len = SPI_MAX_BUF_SIZE;

            spi_message_init(&m);
            spi_message_add_tail(&t, &m);

            ret = spi_sync(spi_dev, &m);
            mutex_unlock(&spi_lock);

            if (ret < 0)
                pr_err("SPI TX failed\n");

            r_cnt++;

            if (rx_cnt > 0) {
                mutex_lock(&net_lock);
                spi_net_receive_packet();
                mutex_unlock(&net_lock);
                rx_cnt--;
            }

            usleep_range(500, 600);
        }

        r_cnt = w_cnt = 0;
    }
    return 0;
}

static int rx_thread_fn(void *data) {
    int ret;
    bool rx_flag = false;

    while (!kthread_should_stop()) {
        ret = gpio_get_value(SI917_IRQ_GPIO);
        if (ret == 1 && !rx_flag) {
            rx_flag = true;
        } else if (ret == 0 && rx_flag) {
            rx_flag = false;
            rx_cnt++;

            if (w_cnt < SPI_BUF_NUM - 1) {
                memset(tx_buf[w_cnt], 0, SPI_MAX_BUF_SIZE);
                w_cnt++;
            }
            spi_pending = true;
            wake_up_interruptible(&spi_wait);
        }
    }
    return 0;
}

static netdev_tx_t spi_net_xmit(struct sk_buff *skb, struct net_device *dev) {
    if (!spi_dev) {
        dev_kfree_skb(skb);
        return NETDEV_TX_OK;
    }

    if (skb->len > SPI_MAX_BUF_SIZE) {
        dev_kfree_skb(skb);
        return NETDEV_TX_OK;
    }

    if (w_cnt < SPI_BUF_NUM - 1) {
        memset(tx_buf[w_cnt], 0, SPI_MAX_BUF_SIZE);
        memcpy(tx_buf[w_cnt], skb->data, skb->len);
        w_cnt++;
        spi_pending = true;
        wake_up_interruptible(&spi_wait);
    }

    dev_kfree_skb(skb);
    return NETDEV_TX_OK;
}

static int spi_net_open(struct net_device *dev) {
    int i;
    if (!gpio_is_valid(SI917_IRQ_GPIO) || !gpio_is_valid(SI917_WAIT_GPIO))
        return -ENODEV;

    gpio_request(SI917_IRQ_GPIO, "spi_net_irq");
    gpio_direction_input(SI917_IRQ_GPIO);

    irq = gpio_to_irq(SI917_IRQ_GPIO);

    gpio_request(SI917_WAIT_GPIO, "spi_net_wait");
    gpio_direction_input(SI917_WAIT_GPIO);

    // spi_thread = kthread_run(spi_thread_fn, NULL, "spi_thread");
    // rx_thread = kthread_run(rx_thread_fn, NULL, "rx_thread");

    /* 워크큐 초기화 */
    for (i=0; i<TEST_CNT; i++) {
        INIT_WORK(&rx_work[i], spi_net_rx_work);
        rwq = create_singlethread_workqueue("spi_net_rx_wq");
        if (!rwq) {
            free_irq(irq);
            gpio_free(SI917_IRQ_GPIO);
            return -ENOMEM;
        }
    }

    netif_start_queue(dev);

    for (i=0; i<10; i++) {
        spi_net_send_arp_request(in_aton("192.168.0.1"));
    }

    spi_pending = true;
    wake_up_interruptible(&spi_wait);

    /* 워크큐 초기화 */
    for (i=0; i<TEST_CNT; i++) {
        INIT_WORK(&tx_work[i], spi_net_rx_work);
        twq = create_singlethread_workqueue("spi_net_rx_wq");
        if (!twq) {
            return -ENOMEM;
        }
    }

    for (i=0; i<TEST_CNT; i++) {
        pr_info("add wq:%d\n", i);
        queue_work(twq, &tx_work[i]);
    }

    return 0;
}



static int spi_net_stop(struct net_device *dev) {
    netif_stop_queue(dev);
    return 0;
}

static int spi_net_set_mac_address(struct net_device *dev, void *p) {
    struct sockaddr *addr = p;

    if (!is_valid_ether_addr(addr->sa_data))  // 유효한 MAC 주소인지 확인
        return -EADDRNOTAVAIL;

    memcpy(dev->dev_addr, addr->sa_data, ETH_ALEN);
    return 0;
}

static const struct net_device_ops spi_netdev_ops = {
    .ndo_open = spi_net_open,
    .ndo_stop = spi_net_stop,
    .ndo_start_xmit = spi_net_xmit,
    .ndo_set_mac_address = spi_net_set_mac_address,  // MAC 주소 변경 지원
};

static int spi_net_probe(struct spi_device *spi) {
    int i;

    spi_net_dev = alloc_etherdev(0);
    if (!spi_net_dev)
        return -ENOMEM;

    spi_net_dev->netdev_ops = &spi_netdev_ops;
    spi_net_dev->mtu = 800;

    spi_dev = spi;

    for (i = 0; i < SPI_BUF_NUM; i++) {
        tx_buf[i] = kmalloc(SPI_MAX_BUF_SIZE, GFP_KERNEL);
        if (!tx_buf[i])
            return -ENOMEM;
    }

    rx_buffer = kmalloc(SPI_MAX_BUF_SIZE, GFP_KERNEL);
    if (!rx_buffer)
        return -ENOMEM;

    register_netdev(spi_net_dev);

    pr_info("SPI network device registered (no struct spi_net_priv)\n");
    return 0;
}

static int spi_net_remove(struct spi_device *spi) {
    int i;

    unregister_netdev(spi_net_dev);
    for (i = 0; i < SPI_BUF_NUM; i++)
        kfree(tx_buf[i]);
    kfree(rx_buffer);

    return 0;
}

static const struct of_device_id spi_net_dt_ids[] = {
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
MODULE_DESCRIPTION("SPI-based Network Device Driver without spi_net_priv");
