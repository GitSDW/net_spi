#include <linux/types.h>
#include <linux/module.h>
#include <linux/mmc/sdio_func.h>
#include <linux/mmc/card.h>
#include <mach/jzmmc.h>
#include <linux/delay.h>


#include <linux/workqueue.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <net/ip.h>

struct sdio_func *func_file;
struct net_device *net_dev;
volatile uint8_t req_stop_queue = 0;
unsigned char *tx_data_buffer;
unsigned char *rx_data_buffer;

static void process_sdio_protocol(struct work_struct *w);

static struct workqueue_struct *sdio_workqueue;
static DECLARE_WORK(sdio_work, process_sdio_protocol);

struct sk_buff_head     skb_tx_head;

int si917_sdio_align_size(int len)
{
    int ret = 0;
    
    ret = sdio_align_size(func_file, len);
    
    
    /*
    // BEGIN For DEBUG --------------------------
    if(len < 256)
    {
        ret = 256;
    }
    else if(len < 512)
    {
        ret = 512;
    }
    else if(len < 768)
    {
        ret = 768;
    }
    else if(len < 1024)
    {
        ret = 1024;
    }
    else if(len < 1024)
    {
        ret = 1024;
    }
    // END For DEBUG ----------------------------
    */
    
    return ret;
}

static int si917_sdio_copy_from_io(struct sdio_func *func,
                                   unsigned int reg_id,
                                   void *dst,
                                   size_t count)
{
	unsigned int sdio_addr = reg_id << 2;
	int ret;

	//WARN(reg_id > 7, "chip only has 7 registers");
	WARN(((uintptr_t)dst) & 3, "unaligned buffer size");
	WARN(count & 3, "unaligned buffer address");

	ret = sdio_memcpy_fromio(func, dst, sdio_addr, count);
    
	return ret;
}

static int si917_sdio_copy_to_io(struct sdio_func *func,
                                 unsigned int reg_id,
                                 const void *src,
                                 size_t count)
{
    unsigned int sdio_addr = reg_id << 2;
    int ret;

    //WARN(reg_id > 7, "chip only has 7 registers");
    WARN(((uintptr_t)src) & 3, "unaligned buffer size");
    WARN(count & 3, "unaligned buffer address");

    ret = sdio_memcpy_toio(func, sdio_addr, (void *)src, count);
    
    return ret;
}

static void si917_sdio_irq_handler(struct sdio_func *func)
{
    int ret;
    int len;
    int i;
    
    struct sk_buff	*skb;
    
    //printk("si917_sdio_irq_handler\n");
    
	ret = si917_sdio_copy_from_io(func, 5, rx_data_buffer, 1536);
    
    /*
    // BEGIN For DEBUG --------------------------
    pr_info("si917_sdio_copy_from_io returns %d\n", ret);
	for(i=0 ; i<2048 ; i++)
    {
		printk(" %d", rx_data_buffer[i]);
        if((i % 10) == 9) printk("\n");
	}
    pr_info("\n");
    // END For DEBUG ----------------------------
    */
    
    // Decode the length
    len = rx_data_buffer[24];
    len *= 256;
    len += rx_data_buffer[25];
    len += 20;
    
    //pr_info("si917_sdio_copy_from_io len = %d\n", len);
    
    if(len < 1500)
    {
        skb = netdev_alloc_skb(net_dev, len);
        skb_put(skb, len);
        
        for(i = 0 ; i < len ; i ++)
        {
            skb->data[i] = rx_data_buffer[i];
        }
        
        skb->protocol = 8;			
        skb->ip_summed = CHECKSUM_UNNECESSARY;
        
        ret = netif_rx_ni(skb);
        
        //pr_info("netif_rx_ni returns %d\n", ret);
    }
    else
    {
        pr_info("Discard the sdio packet\n");
    }
}

static int si917_sdio_irq_subscribe(struct sdio_func *func)
{
    int ret;
    sdio_claim_host(func);
    ret = sdio_claim_irq(func, si917_sdio_irq_handler);
    sdio_release_host(func);
    
    return ret;
}

static int si917_sdio_irq_unsubscribe(struct sdio_func *func)
{
    int ret;
    sdio_claim_host(func);
    ret = sdio_release_irq(func);
    sdio_release_host(func);
    
    return ret;
}

static netdev_tx_t si917_send_packet(struct sk_buff *skb,
                     struct net_device *dev)
{
    // pr_info("Begin si917_send_packet\n");
    
    /*
    // BEGIN For DEBUG --------------------------
    int i;
    
    pr_info("skb->protocol = %x, len = %d\n", skb->protocol, skb->len);
    pr_info("skb->data =");
    for(i = 0 ; i < 10 ; i ++)
    {
        printk(" %02X", skb->data[i]);
    }
    // END For DEBUG ----------------------------
    */
    
    skb_queue_tail(&skb_tx_head, skb);
    
    if(!work_pending(&sdio_work))
    {
        queue_work(sdio_workqueue, &sdio_work);
        //queue_work(system_highpri_wq, &sdio_work);
	}
    
    if((req_stop_queue == 0) && (skb_queue_len(&skb_tx_head) > 200))
    {
        printk("req_stop_queue = 1\n");
        req_stop_queue = 1;
        netif_stop_queue(net_dev);
    }
    
    return NETDEV_TX_OK;
}

static void process_sdio_protocol(struct work_struct *w)
{
    int i;
    struct sk_buff *skb;
    int aligned_len = 0;
    int ret = -1;
    unsigned int checksum = 0;
    //unsigned char num_free_uplink_wr_slot = 0;
    
    
    //printk("process_sdio_protocol\n");
    
    while ((skb = skb_dequeue(&skb_tx_head)) != NULL)
    {
        /*
        // Query the number of free_uplink buffer slot
        while(num_free_uplink_wr_slot < 2)
        {
            sdio_claim_host(func_file);
            num_free_uplink_wr_slot = sdio_readb(func_file, 0, &ret);
            sdio_release_host(func_file);
            printk("free 1 = %d\n", num_free_uplink_wr_slot);
            
            usleep_range(1000, 2000);
            
            sdio_claim_host(func_file);
            num_free_uplink_wr_slot = sdio_readb(func_file, 0, &ret);
            sdio_release_host(func_file);
            printk("free 2 = %d\n", num_free_uplink_wr_slot);
                                                 
            if((num_free_uplink_wr_slot > 16) || (ret != 0))
            {
                printk("num_free_uplink_wr_slot = %d, ret = %d\n", num_free_uplink_wr_slot, ret);
                num_free_uplink_wr_slot = 0;
            }
            else
            {
                //printk("num_free_uplink_wr_slot = %d\n", num_free_uplink_wr_slot);
            }
            
            usleep_range(1000, 2000);
        }
        */
        
        for(i = 0 ; i < skb->len ; i ++)
        {
            tx_data_buffer[i] = skb->data[i];
        }
        
        // BEGIN For DEBUG --------------------------
        //pr_info("tx_data_buffer =");
        //for(i = 0 ; i < 10 ; i ++)
        //{
        //    printk(" %02X", tx_data_buffer[i]);
        //}
        // END For DEBUG ----------------------------
        
        // BEGIN For DEBUG --------------------------
        checksum = 0;
        for(i = 0 ; i < skb->len ; i ++)
        {
            checksum += tx_data_buffer[i];
        }
        tx_data_buffer[skb->len] = (unsigned char) checksum;
        tx_data_buffer[skb->len + 1] = 0xAA;
        tx_data_buffer[skb->len + 2] = 0x55;
        // END For DEBUG ----------------------------
        
        aligned_len = si917_sdio_align_size(skb->len + 3);
        
        ret = -1;
        
        while(ret != 0)
        {
            sdio_claim_host(func_file);
            
            ret = si917_sdio_copy_to_io(func_file,
                                        5,
                                        tx_data_buffer,
                                        aligned_len);
                                        
            if(ret != 0) printk("si917_sdio_copy_to_io return %d\n", ret);
            
            sdio_release_host(func_file);
            
            //usleep_range(500, 1000);
        }
        
        if((req_stop_queue == 1) && (skb_queue_len(&skb_tx_head) < 10))
        {
            printk("req_stop_queue = 0\n");
            req_stop_queue = 0;
            netif_wake_queue(net_dev);
        }
        
        dev_kfree_skb(skb);
        
        //num_free_uplink_wr_slot --;
    }
}

static const struct net_device_ops si917_netdev_ops = {
    .ndo_start_xmit        = si917_send_packet
    /* TBD */
};

void si917_setup(struct net_device *dev)
{
    /* TBD */
}

static int si917_sdio_probe(struct sdio_func *func,
                const struct sdio_device_id *id)
{
    int ret;
    
    printk("si917_sdio_probe\n");

    tx_data_buffer = (unsigned char*) kmalloc(4096, GFP_KERNEL);
    rx_data_buffer = (unsigned char*) kmalloc(4096, GFP_KERNEL);
    
    net_dev = alloc_netdev(0, "eth0", si917_setup);
    
    net_dev->netdev_ops = &si917_netdev_ops;
    
    ret = register_netdev(net_dev);
    
    skb_queue_head_init(&skb_tx_head);
    
    sdio_workqueue = create_workqueue("SDIO protocol workqueue");
    
    if (func->num != 1) {
        dev_err(&func->dev, "SDIO function number is %d while it should always be 1 (unsupported chip?)\n", func->num);
        return -ENODEV;
    }

    func_file = func;
    func->card->quirks |= MMC_QUIRK_LENIENT_FN0 |
                  MMC_QUIRK_BLKSZ_FOR_BYTE_MODE |
                  MMC_QUIRK_BROKEN_BYTE_MODE_512;

    sdio_claim_host(func);
    ret = sdio_enable_func(func);
    //printk("sdio_enable_func ret = %d\n", ret);
    
    // Block of 64 bytes is more efficient than 512B for frame sizes < 4k
    ret = sdio_set_block_size(func, 256);
    //printk("sdio_set_block_size ret = %d\n", ret);
    
    sdio_release_host(func);
    
    if (ret)
        goto err0;

    ret = si917_sdio_irq_subscribe(func_file);
    
    if (ret)
        goto err1;
    
    return 0;
err1:
    printk("si917_sdio_probe err1\n");
    
    sdio_claim_host(func);
    sdio_disable_func(func);
    sdio_release_host(func);
    
err0:
    printk("si917_sdio_probe ret = %d\n", ret);
    
    return ret;
}

static void si917_sdio_remove(struct sdio_func *func)
{
    si917_sdio_irq_unsubscribe(func);
    sdio_claim_host(func);
    sdio_disable_func(func);
    sdio_release_host(func);
}

#define SDIO_VENDOR_ID_SILABS        0x041b
#define SDIO_DEVICE_ID_SILABS_SI917  0x0917
static const struct sdio_device_id si917_sdio_ids[] = {
    { SDIO_DEVICE(SDIO_VENDOR_ID_SILABS, SDIO_DEVICE_ID_SILABS_SI917) },
    { },
};

struct sdio_driver si917_sdio_driver = {
    .name = "si917-sdio",
    .id_table = si917_sdio_ids,
    .probe = si917_sdio_probe,
    .remove = si917_sdio_remove,
    .drv = {
        .owner = THIS_MODULE,
    }
};

static int __init si917_sdio_init(void)
{
    int ret;
    printk("si917_sdio_init\n");
    ret = jzmmc_manual_detect(1, 1);
    printk("jzmmc_manual_detect returns %d\n", ret);
    
    ret = sdio_register_driver(&si917_sdio_driver);
    printk("sdio_register_driver returns %d\n", ret);
    
    return ret;
}

static void __exit si917_sdio_exit(void)
{
    printk("si917_sdio_exit\n");
    return sdio_unregister_driver(&si917_sdio_driver);
}

module_init(si917_sdio_init);
module_exit(si917_sdio_exit);


MODULE_AUTHOR("Silabs ODC");
MODULE_LICENSE("GPL");