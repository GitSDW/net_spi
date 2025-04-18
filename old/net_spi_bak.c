#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/spi/spi.h>
#include <linux/etherdevice.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>

#define SPI_MAX_BUF_SIZE 1024

struct spi_net_priv {
    struct net_device *net_dev;
    struct spi_device *spi_dev;
    struct workqueue_struct *tx_wq;
    struct work_struct tx_work;
    struct sk_buff *tx_skb;
    unsigned char *tx_buffer;
    struct mutex tx_lock;
};

static void spi_net_tx_work(struct work_struct *work) {
    struct spi_net_priv *priv = container_of(work, struct spi_net_priv, tx_work);
    struct spi_device *spi = priv->spi_dev;
    struct sk_buff *skb;
    struct spi_transfer t = {
        .tx_buf = priv->tx_buffer,
        .len = SPI_MAX_BUF_SIZE,
    };
    struct spi_message m;
    int ret;

    mutex_lock(&priv->tx_lock);
    skb = priv->tx_skb;
    if (!skb) {
        mutex_unlock(&priv->tx_lock);
        return;
    }

    memset(priv->tx_buffer, 0, SPI_MAX_BUF_SIZE);
    memcpy(priv->tx_buffer, skb->data, skb->len);
    
    spi_message_init(&m);
    spi_message_add_tail(&t, &m);
    ret = spi_sync(spi, &m);
    if (ret < 0)
        pr_err("SPI TX failed\n");

    dev_kfree_skb(skb);
    priv->tx_skb = NULL;
    mutex_unlock(&priv->tx_lock);
}

static netdev_tx_t spi_net_xmit(struct sk_buff *skb, struct net_device *dev) {
    struct spi_net_priv *priv = netdev_priv(dev);

    if (skb->len > SPI_MAX_BUF_SIZE) {
        dev_kfree_skb(skb);
        return NETDEV_TX_OK;
    }

    mutex_lock(&priv->tx_lock);
    priv->tx_skb = skb;
    queue_work(priv->tx_wq, &priv->tx_work);
    mutex_unlock(&priv->tx_lock);

    return NETDEV_TX_OK;
}

static int spi_net_open(struct net_device *dev) {
    struct spi_net_priv *priv = netdev_priv(dev);
    netif_start_queue(dev);
    return 0;
}

static int spi_net_stop(struct net_device *dev) {
    struct spi_net_priv *priv = netdev_priv(dev);
    netif_stop_queue(dev);
    return 0;
}

static const struct net_device_ops spi_netdev_ops = {
    .ndo_open = spi_net_open,
    .ndo_stop = spi_net_stop,
    .ndo_start_xmit = spi_net_xmit,
};

static int spi_net_probe(struct spi_device *spi) {
    struct net_device *net_dev;
    struct spi_net_priv *priv;

    net_dev = alloc_etherdev(sizeof(struct spi_net_priv));
    if (!net_dev)
        return -ENOMEM;

    priv = netdev_priv(net_dev);
    priv->net_dev = net_dev;
    priv->spi_dev = spi;
    mutex_init(&priv->tx_lock);

    priv->tx_buffer = kmalloc(SPI_MAX_BUF_SIZE, GFP_KERNEL);
    if (!priv->tx_buffer) {
        free_netdev(net_dev);
        return -ENOMEM;
    }

    priv->tx_wq = create_singlethread_workqueue("spi_net_tx_wq");
    INIT_WORK(&priv->tx_work, spi_net_tx_work);
    net_dev->netdev_ops = &spi_netdev_ops;

    if (register_netdev(net_dev)) {
        kfree(priv->tx_buffer);
        free_netdev(net_dev);
        return -EIO;
    }

    spi_set_drvdata(spi, priv);
    return 0;
}

static int spi_net_remove(struct spi_device *spi) {
    struct spi_net_priv *priv = spi_get_drvdata(spi);
    unregister_netdev(priv->net_dev);
    destroy_workqueue(priv->tx_wq);
    kfree(priv->tx_buffer);
    free_netdev(priv->net_dev);
    return 0;
}

static struct spi_driver spi_net_driver = {
    .driver = {
        .name = "spi_net",
    },
    .probe = spi_net_probe,
    .remove = spi_net_remove,
};

module_spi_driver(spi_net_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SPI Network Driver Developer");
MODULE_DESCRIPTION("SPI-based Network Device Driver using Workqueue");
