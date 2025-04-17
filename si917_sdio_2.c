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
#include <linux/wireless.h>
#include <linux/inetdevice.h>
#include <net/ip.h>
#include <net/iw_handler.h>

struct sdio_func *func_file;
struct net_device *net_dev;
volatile uint8_t req_stop_queue = 0;
volatile uint8_t overflow_917 = 0;
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

#define POS_MARK       0
#define POS_LEN_PACKET 1
#define POS_MAC_DST 3
#define POS_MAC_SRC 9
#define POS_COMMON_HEADER 15
#define POS_IP_TYPE 17
#define POS_LEN_COMMAND 19
#define POS_DATA_COMMAND 20

#define CUSTOM_ETHERTYPE 0x8386
#define SIOCS_CUSTOM_MAC 0xAA11
#define SIOCS_CUSTOM_IP 0xAA22

#define SIOCS_CUSTOM_ALARM_OVERFLOW 0xAB23
#define SIOCS_CUSTOM_CLEAR_OVERFLOW 0xBC64

#define POS_DATA_REQ 20
#define POS_DATA_IPV4 21
#define POS_DATA_MAC 21

#define REQUEST_INFOR 1
#define REPLY_INFOR   2

unsigned char ip_v4_return[4];
struct completion reply_done;
static void si917_sdio_irq_handler(struct sdio_func *func)
{
    int ret;
    int len;
    int i;
    
    struct sk_buff	*skb;
    
	ret = si917_sdio_copy_from_io(func, 5, rx_data_buffer, 1536);
    
    // Decode the length
    len = rx_data_buffer[POS_LEN_PACKET]*256;
    len += rx_data_buffer[POS_LEN_PACKET+1];

    // pr_info("917 sdio rx:\n");
    // for(i=0;i<len+3;i++) {
    //     pr_info("%02x ", rx_data_buffer[i]);
    // }
    // pr_info("\n");

    if(len < 1530)
    {
        if(rx_data_buffer[POS_COMMON_HEADER] == CUSTOM_ETHERTYPE>>8 && (rx_data_buffer[POS_COMMON_HEADER+1] == (unsigned char)((CUSTOM_ETHERTYPE)&(0xFF)))) {
            printk("917 sdio rx CUSTOM_ETHERTYPE:\n");
            for(i=0;i<len+3;i++) {
                printk("%02x ", rx_data_buffer[i]);
            }
            printk("\n");
            if(rx_data_buffer[POS_IP_TYPE] == SIOCS_CUSTOM_MAC>>8 && rx_data_buffer[POS_IP_TYPE+1] == (unsigned char)(SIOCS_CUSTOM_MAC&0xFF) && rx_data_buffer[POS_DATA_REQ]==REPLY_INFOR) {
                printk("Adding MAC\n");
                memcpy(net_dev->dev_addr, &rx_data_buffer[POS_DATA_MAC], 6);
            }
            else if(rx_data_buffer[POS_IP_TYPE] == SIOCS_CUSTOM_IP>>8 && rx_data_buffer[POS_IP_TYPE+1] == (unsigned char)(SIOCS_CUSTOM_IP&0xFF) && rx_data_buffer[POS_DATA_REQ]==REPLY_INFOR) {
                printk("Adding IP\n");
                memcpy(ip_v4_return, &rx_data_buffer[POS_DATA_IPV4], 4);
                complete(&reply_done);
            }
            // else if(rx_data_buffer[POS_IP_TYPE] == SIOCS_CUSTOM_ALARM_OVERFLOW>>8 && rx_data_buffer[POS_IP_TYPE+1] == (unsigned char)(SIOCS_CUSTOM_ALARM_OVERFLOW&0xFF)) {
            //     // overflow_917 = 1;
            //     if(overflow_917 == 0) {
            //         overflow_917 = 1;
            //         netif_stop_queue(net_dev);
            //         pr_info("Overflow to alarm\n");
            //     }
            //     else {
            //         pr_info("Overflow already alarm\n");
            //     }
            // }
            // else if(rx_data_buffer[POS_IP_TYPE] == SIOCS_CUSTOM_CLEAR_OVERFLOW>>8 && rx_data_buffer[POS_IP_TYPE+1] == (unsigned char)(SIOCS_CUSTOM_CLEAR_OVERFLOW&0xFF)) {
            //     // overflow_917 = 0;req_stop_queue
            //     if(overflow_917 == 1) {
            //         overflow_917 = 0;
            //         if(req_stop_queue == 0) {
            //             netif_wake_queue(net_dev);
            //             pr_info("Overflow to clear\n");
            //         }
            //         else {
            //             pr_info("Still overflow driver Tx\n");
            //         }
            //     }
            // }
            return;
        }

        skb = netdev_alloc_skb(net_dev, len);
        skb_put(skb, len);
        
        for(i = 0 ; i < len ; i ++)
        {
            skb->data[i] = rx_data_buffer[i+POS_MAC_DST];
        }
        
        skb->protocol = eth_type_trans(skb,net_dev);			
        skb->ip_summed = CHECKSUM_UNNECESSARY;
        
        // pr_info("917 Socket:\n");
        // for(i=0;i<len;i++) {
        //     pr_info("%02x ", skb->data[i]);
        // }
        // pr_info("\n");

        ret = netif_rx_ni(skb);
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
   int i;
   printk("skb->data =");
   for(i = 0 ; i < 10 ; i ++)
   {
       printk(" %02X", skb->data[i]);
   }


    skb_queue_tail(&skb_tx_head, skb);
    
    if(!work_pending(&sdio_work))
    {
        queue_work(sdio_workqueue, &sdio_work);
	}
    // else printk("queue_work busy");
    
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

    while ((skb = skb_dequeue(&skb_tx_head)) != NULL && (overflow_917==0))
    {
        tx_data_buffer[POS_MARK] = 0xFF;
        tx_data_buffer[POS_LEN_PACKET] = (skb->len)>>8;
        tx_data_buffer[POS_LEN_PACKET+1] = (skb->len)&0xFF;
        for(i = 0 ; i < skb->len ; i ++)
        {
            tx_data_buffer[i+POS_MAC_DST] = skb->data[i];
        }

        checksum = 0;
        for(i = 0 ; i < skb->len+POS_MAC_DST ; i ++)
        {
            checksum += tx_data_buffer[i];
        }
        tx_data_buffer[skb->len+POS_MAC_DST] = (unsigned char) checksum;
        tx_data_buffer[skb->len+POS_MAC_DST+1] = 0xAA;
        tx_data_buffer[skb->len+POS_MAC_DST+2] = 0x55;
        
        aligned_len = si917_sdio_align_size(skb->len+POS_MAC_DST+3);
        
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
        }
        
        if((req_stop_queue == 1) && (skb_queue_len(&skb_tx_head) < 10))
        {
            printk("req_stop_queue = 0\n");
            req_stop_queue = 0;
            if(overflow_917==0) {
                netif_wake_queue(net_dev);
            }
            else {
                printk("still overflow 917");
            }
        }
        printk("sent to sdio");
        dev_kfree_skb(skb);
    }
}

static const struct net_device_ops si917_netdev_ops = {
    .ndo_start_xmit        = si917_send_packet
    /* TBD */
};

static const unsigned char fixed_mac[ETH_ALEN] = {0x8C, 0x65, 0xA3, 0x19, 0x9A, 0x90};

static int si917_wl_update_ip_from_917(struct net_device *netdev,
    struct iw_request_info *info,
    union iwreq_data *data, char *extra) {

    printk("Send get ip commnand\n");
    unsigned long rc;
    struct sk_buff *skb;
    struct ethhdr *eth;
    int min_payload_size = 46;  
    int data_len;
    char command[100];
    char mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    command[0] = SIOCS_CUSTOM_IP>>8;
    command[1] = SIOCS_CUSTOM_IP&0xFF;
    command[2] = 1;//len
    command[3] = REQUEST_INFOR;
    data_len = 5;

    int pad_size = (data_len < min_payload_size) ? (min_payload_size - data_len) : 0;
    int total_len = sizeof(struct ethhdr) + data_len + pad_size;
    skb = alloc_skb(total_len + NET_IP_ALIGN, GFP_ATOMIC);
    if (!skb) {
        printk("alloc_skb failed\n");
        return -1;
    }
    skb_reserve(skb, NET_IP_ALIGN);  

    eth = (struct ethhdr *)skb_put(skb, sizeof(struct ethhdr));
    memcpy(eth->h_dest, mac, ETH_ALEN);           
    memcpy(eth->h_source, mac, ETH_ALEN);   
    eth->h_proto = htons(CUSTOM_ETHERTYPE);            

    memcpy(skb_put(skb, data_len), command, data_len);

    if (pad_size > 0) {
        memset(skb_put(skb, pad_size), 0x00, pad_size);  
    }

    skb->dev = net_dev;
    skb->protocol = eth->h_proto;
    skb->pkt_type = PACKET_OUTGOING;  
    skb->ip_summed = CHECKSUM_NONE;   


    init_completion(&reply_done);

    skb_reset_mac_header(skb);        

    skb_queue_tail(&skb_tx_head, skb);

    if(!work_pending(&sdio_work))
    {
        queue_work(sdio_workqueue, &sdio_work);
    }
    
    if((req_stop_queue == 0) && (skb_queue_len(&skb_tx_head) > 200))
    {
        printk("req_stop_queue = 1\n");
        req_stop_queue = 1;
        netif_stop_queue(net_dev);
    }
    
    rc = wait_for_completion_timeout(&reply_done, HZ * 4); 
    if(rc) {
        printk("transfer ip information\n");
        ((unsigned char*)(data->data.pointer))[0] = 1;
        memcpy(&(((unsigned char*)(data->data.pointer))[1]), ip_v4_return, 4);
    }
    else {
        printk("timeout\n");
        extra[0] = 0;
    }
    return 0;
}

static int si917_wl_set_essid(struct net_device *netdev,
    struct iw_request_info *info,
    union iwreq_data *data, char *extra) {

    printk("si917_wl_set_essid len=%d flag=%d\n",
            data->essid.length, data->essid.flags);
    if (IW_ESSID_MAX_SIZE < data->essid.length)
        return -EINVAL;

    if (data->essid.flags) {
        printk("ssid %s\n", extra);
        struct sk_buff *skb;
        struct ethhdr *eth;
        int min_payload_size = 46;  
        int data_len;
        char command[100];
        char mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        command[0] = SIOCSIWESSID>>8;
        command[1] = SIOCSIWESSID&0xFF;
        command[2] = data->essid.length;
        memcpy(&command[3], extra, data->essid.length);
        data_len = 3+data->essid.length;

        int pad_size = (data_len < min_payload_size) ? (min_payload_size - data_len) : 0;
        int total_len = sizeof(struct ethhdr) + data_len + pad_size;
        skb = alloc_skb(total_len + NET_IP_ALIGN, GFP_ATOMIC);
        if (!skb) {
            printk("alloc_skb failed\n");
            return -1;
        }
        skb_reserve(skb, NET_IP_ALIGN);  
    
        eth = (struct ethhdr *)skb_put(skb, sizeof(struct ethhdr));
        memcpy(eth->h_dest, mac, ETH_ALEN);           
        memcpy(eth->h_source, netdev->dev_addr, ETH_ALEN);   
        eth->h_proto = htons(CUSTOM_ETHERTYPE);            
    
        memcpy(skb_put(skb, data_len), command, data_len);
    
        if (pad_size > 0) {
            memset(skb_put(skb, pad_size), 0x00, pad_size);  
        }
    
        skb->dev = netdev;
        skb->protocol = eth->h_proto;
        skb->pkt_type = PACKET_OUTGOING;  
        skb->ip_summed = CHECKSUM_NONE;   
    
        skb_reset_mac_header(skb);        
    
        skb_queue_tail(&skb_tx_head, skb);
    
        if(!work_pending(&sdio_work))
        {
            queue_work(sdio_workqueue, &sdio_work);
        }
        
        if((req_stop_queue == 0) && (skb_queue_len(&skb_tx_head) > 200))
        {
            printk("req_stop_queue = 1\n");
            req_stop_queue = 1;
            netif_stop_queue(net_dev);
        }
    } else {
        printk("data->essid.flags false\n");
    }
    return 0;
}

static int si917_wl_set_encode(struct net_device *netdev,
			       struct iw_request_info *info,
			       union iwreq_data *data, char *extra)
{
	// struct iw_point *enc = &data->encoding;
	__u16 flags;
	unsigned long irqflag;
	int key_index, index_specified;
	int ret = 0;

	flags = data->encoding.flags & IW_ENCODE_FLAGS;
	printk("key_len = %d\n", data->encoding.length);
    printk("key conten: %s", extra);
	printk("flag=%x\n", data->encoding.flags & IW_ENCODE_FLAGS);
    
    struct sk_buff *skb;
    struct ethhdr *eth;
    int min_payload_size = 46;
    int data_len;
    char command[100];
    char mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    command[0] = SIOCSIWENCODE>>8;
    command[1] = SIOCSIWENCODE&0xFF;
    command[2] = data->encoding.length;
    memcpy(&command[3], extra, data->encoding.length);
    data_len = 3+data->encoding.length;

    int pad_size = (data_len < min_payload_size) ? (min_payload_size - data_len) : 0;
    int total_len = sizeof(struct ethhdr) + data_len + pad_size;

    printk("total_len + NET_IP_ALIGN: %d", total_len + NET_IP_ALIGN);

    skb = alloc_skb(total_len + NET_IP_ALIGN, GFP_ATOMIC);
    if (!skb) {
        printk("alloc_skb failed\n");
        return -1;
    }

    skb_reserve(skb, NET_IP_ALIGN); 

    eth = (struct ethhdr *)skb_put(skb, sizeof(struct ethhdr));
    memcpy(eth->h_dest, mac, ETH_ALEN);           
    memcpy(eth->h_source, netdev->dev_addr, ETH_ALEN);   
    eth->h_proto = htons(CUSTOM_ETHERTYPE);           

    memcpy(skb_put(skb, data_len), command, data_len);

    if (pad_size > 0) {
        memset(skb_put(skb, pad_size), 0x00, pad_size); 
    }

    skb->dev = netdev;
    skb->protocol = eth->h_proto;
    skb->pkt_type = PACKET_OUTGOING; 
    skb->ip_summed = CHECKSUM_NONE; 

    skb_reset_mac_header(skb);      

    skb_queue_tail(&skb_tx_head, skb);

    if(!work_pending(&sdio_work))
    {
        queue_work(sdio_workqueue, &sdio_work);
    }
    
    if((req_stop_queue == 0) && (skb_queue_len(&skb_tx_head) > 200))
    {
        printk("req_stop_queue = 1\n");
        req_stop_queue = 1;
        netif_stop_queue(net_dev);
    }

	return 0;
}

static const iw_handler si917_wl_handler[] =
{
	// IW_HANDLER(SIOCGIWNAME, si917_wl_get_name),
	// IW_HANDLER(SIOCGIWRANGE, si917_wl_get_range),
	// IW_HANDLER(SIOCSIWSCAN, si917_wl_set_scan),
	// IW_HANDLER(SIOCGIWSCAN, si917_wl_get_scan),
	// IW_HANDLER(SIOCSIWAUTH, si917_wl_set_auth),
	// IW_HANDLER(SIOCGIWAUTH, si917_wl_get_auth),
	IW_HANDLER(SIOCSIWESSID, si917_wl_set_essid),
	// IW_HANDLER(SIOCGIWESSID, si917_wl_get_essid),
	IW_HANDLER(SIOCSIWENCODE, si917_wl_set_encode),
	// IW_HANDLER(SIOCGIWENCODE, si917_wl_get_encode),
	// IW_HANDLER(SIOCSIWAP, si917_wl_set_ap),
	// IW_HANDLER(SIOCGIWAP, si917_wl_get_ap),
	// IW_HANDLER(SIOCSIWENCODEEXT, si917_wl_set_encodeext),
	// IW_HANDLER(SIOCGIWENCODEEXT, si917_wl_get_encodeext),
	// IW_HANDLER(SIOCSIWMODE, si917_wl_set_mode),
	// IW_HANDLER(SIOCGIWMODE, si917_wl_get_mode),
	// IW_HANDLER(SIOCGIWNICKN, si917_wl_get_nick),
    IW_HANDLER(SIOCIWFIRSTPRIV, si917_wl_update_ip_from_917),
};

static const struct iw_handler_def si917_wl_handler_def = {
	.num_standard		= ARRAY_SIZE(si917_wl_handler),
	.standard		= si917_wl_handler,
	// .get_wireless_stats	= gelic_wl_get_wireless_stats,
};

void si917_setup(struct net_device *dev)
{
    /* TBD */
    ether_setup(dev);
    // dev->flags |= IFF_NOARP;
    dev->flags &= ~IFF_NOARP;
    // memcpy(dev->dev_addr, fixed_mac, ETH_ALEN);

	dev->netdev_ops = &si917_netdev_ops;
	dev->wireless_handlers = &si917_wl_handler_def;

    // dev->ethtool_ops = &si917_wl_ethtool_ops;
    // dev->wireless_data = &wl->wireless_data;
}

static int si917_sdio_probe(struct sdio_func *func,
                const struct sdio_device_id *id)
{
    int ret;
    
    printk("si917_sdio_probe\n");

    tx_data_buffer = (unsigned char*) kmalloc(4096, GFP_KERNEL);
    rx_data_buffer = (unsigned char*) kmalloc(4096, GFP_KERNEL);
    
    net_dev = alloc_netdev(0, "wlan0", si917_setup);
    
    
    
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
    
    printk("Send get mac commnand\n");
    struct sk_buff *skb;
    struct ethhdr *eth;
    int min_payload_size = 46;  
    int data_len;
    char command[100];
    char mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    command[0] = SIOCS_CUSTOM_MAC>>8;
    command[1] = SIOCS_CUSTOM_MAC&0xFF;
    command[2] = 1;//len
    command[3] = REQUEST_INFOR;
    data_len = 4;

    int pad_size = (data_len < min_payload_size) ? (min_payload_size - data_len) : 0;
    int total_len = sizeof(struct ethhdr) + data_len + pad_size;
    skb = alloc_skb(total_len + NET_IP_ALIGN, GFP_ATOMIC);
    if (!skb) {
        printk("alloc_skb failed\n");
        return -1;
    }
    skb_reserve(skb, NET_IP_ALIGN);  

    eth = (struct ethhdr *)skb_put(skb, sizeof(struct ethhdr));
    memcpy(eth->h_dest, mac, ETH_ALEN);           
    memcpy(eth->h_source, mac, ETH_ALEN);   
    eth->h_proto = htons(CUSTOM_ETHERTYPE);            

    memcpy(skb_put(skb, data_len), command, data_len);

    if (pad_size > 0) {
        memset(skb_put(skb, pad_size), 0x00, pad_size);  
    }

    skb->dev = net_dev;
    skb->protocol = eth->h_proto;
    skb->pkt_type = PACKET_OUTGOING;  
    skb->ip_summed = CHECKSUM_NONE;   

    skb_reset_mac_header(skb);        

    skb_queue_tail(&skb_tx_head, skb);

    if(!work_pending(&sdio_work))
    {
        queue_work(sdio_workqueue, &sdio_work);
    }
    
    if((req_stop_queue == 0) && (skb_queue_len(&skb_tx_head) > 200))
    {
        printk("req_stop_queue = 1\n");
        req_stop_queue = 1;
        netif_stop_queue(net_dev);
    }

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