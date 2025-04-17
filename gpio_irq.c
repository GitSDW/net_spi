#include <linux/module.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/init.h>

#define GPIO_NUM 50  // 사용할 GPIO 핀 번호 (라즈베리파이 등에서 적절한 핀으로 변경 가능)

static unsigned int irq_number;
static int irq_counter = 0;

// 인터럽트 핸들러 함수
static irqreturn_t gpio_irq_handler(int irq, void *dev_id) {
    irq_counter++;
    pr_info("GPIO Interrupt Occurred! Count: %d\n", irq_counter);
    return IRQ_HANDLED;
}

static int __init gpio_irq_init(void) {
    int result;

    // GPIO 요청
    if (!gpio_is_valid(GPIO_NUM)) {
        pr_err("Invalid GPIO %d\n", GPIO_NUM);
        return -ENODEV;
    }
    gpio_request(GPIO_NUM, "gpio_irq");
    gpio_direction_input(GPIO_NUM);
    
    // GPIO에 대한 IRQ 번호 가져오기
    irq_number = gpio_to_irq(GPIO_NUM);
    pr_info("GPIO %d mapped to IRQ %d\n", GPIO_NUM, irq_number);

    // 인터럽트 요청 (RISING 및 FALLING 트리거 설정 가능)
    result = request_irq(irq_number, gpio_irq_handler, IRQF_TRIGGER_RISING, "gpio_irq_handler", NULL);
    if (result) {
        pr_err("Failed to request IRQ %d\n", irq_number);
        return result;
    }

    pr_info("GPIO Interrupt Module Loaded\n");
    return 0;
}

static void __exit gpio_irq_exit(void) {
    free_irq(irq_number, NULL);
    gpio_free(GPIO_NUM);
    pr_info("GPIO Interrupt Module Unloaded\n");
}

module_init(gpio_irq_init);
module_exit(gpio_irq_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("GPIO Interrupt Example");
