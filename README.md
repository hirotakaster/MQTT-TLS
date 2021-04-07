# MQTT-TLS for Photon, Spark Core
<a href="http://mqtt.org/" target=_blank>MQTT</a> publish/subscribe TLS library for Photon, Spark Core. This library based <a href="https://github.com/hirotakaster/MQTT">MQTT for Photon, Spark Core</a> and mbedTLS 2.16.3.

## Chiper List
* TLS_RSA_WITH_AES_[128|256]_GCM_SHA[1|256|512]
* TLS_ECDHE_ECDSA_WITH_AES_[128|256]_GCM_SHA[385|256]
* TLS_EMPTY_RENOGOTIATION_INFO_SCSV


## Source Code
This lightweight library source code are only 2 files. firmware -> MQTT-TLS.cpp, MQTT-TLS.h.

Application can use QOS0,1,2 and retain flag when send a publish message.

This library tested on test.mosquitto.org, mqtt.eclipse.org, AWS IoT Gateway, Google IoT Core, Azure IoT Hub MQTT servers.


## Example
Some sample sketches for Spark Core and Photon included(firmware/examples/).
 - a1-example.ino	: simple pub/sub sample. 
 
```C++

#include "MQTT-TLS.h"

void callback(char* topic, byte* payload, unsigned int length);

#define LET_ENCRYPT_CA_PEM                                              \
"-----BEGIN CERTIFICATE----- \r\n"                                      \
"MIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAw\r\n"  \
"TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\r\n"  \
"cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAw\r\n"  \
"WhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg\r\n"  \
"RW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\r\n"  \
"AoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cP\r\n"  \
"R5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdx\r\n"  \
"sxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8Zutm\r\n"  \
"NHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxg\r\n"  \
"Z3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG\r\n"  \
"/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMC\r\n"  \
"AYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYB\r\n"  \
"Af8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaA\r\n"  \
"FHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw\r\n"  \
"AoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRw\r\n"  \
"Oi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQB\r\n"  \
"gt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6W\r\n"  \
"PTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wl\r\n"  \
"ikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQz\r\n"  \
"CkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BIm\r\n"  \
"lJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4\r\n"  \
"avAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2\r\n"  \
"yJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1O\r\n"  \
"yK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90Ids\r\n"  \
"hCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+\r\n"  \
"HlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6Zv\r\n"  \
"MldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqX\r\n"  \
"nLRbwHOoq7hHwg==\r\n"  \
"-----END CERTIFICATE-----"
const char letencryptCaPem[] = LET_ENCRYPT_CA_PEM;

/**
 * if want to use IP address,
 * byte server[] = { XXX,XXX,XXX,XXX };
 * MQTT client(server, 1883, callback);
 * want to use domain name,
 * MQTT client("www.sample.com", 1883, callback);
 * mqtt.eclipse.org is Eclipse Open MQTT Broker: https://iot.eclipse.org/getting-started
 **/
MQTT client("mqtt.eclipse.org", 8883, callback);

// recieve message
void callback(char* topic, byte* payload, unsigned int length) {
    char p[length + 1];
    memcpy(p, payload, length);
    p[length] = NULL;
    String message(p);

    if (message.equals("RED"))
        RGB.color(255, 0, 0);
    else if (message.equals("GREEN"))
        RGB.color(0, 255, 0);
    else if (message.equals("BLUE"))
        RGB.color(0, 0, 255);
    else
        RGB.color(255, 255, 255);
    delay(1000);
}

#define ONE_DAY_MILLIS (24 * 60 * 60 * 1000)
unsigned long lastSync = millis();
void setup() {
    if (millis() - lastSync > ONE_DAY_MILLIS) {
        Particle.syncTime();
        lastSync = millis();
    }

    RGB.control(true);

    // enable tls. set Root CA pem file.
    // if you don't use TLS, comment out this line.
    client.enableTls(letencryptCaPem, sizeof(letencryptCaPem));
    Serial.println("tls enable");

    // connect to the server
    client.connect("sparkclient");

    // publish/subscribe
    if (client.isConnected()) {
        Serial.println("client connected");
        client.publish("outTopic/message", "hello world");
        client.subscribe("inTopic/message");
    }
}

void loop() {
    if (client.isConnected())
        client.loop();
    delay(200);
}

```

## Configure mbedTLS options
Developer could easy to change the mbedTLS options (mbedtls/config.h) for application and firmware size. This library use a lot of Flash area for encryption method and limit to user application size. Because of that's developer could enable/disable the mbedTLS option with comment out the option parameters for the Flash spaces. When enable/disable the option parameter, it's carefully check the server/application TLS connectivity and security.

Here is application firmware size(byte) and mbedTLS options on Particle Workbench(local compiler).

| device | RSA/ECDSA,ECDH(default) | RSA only | remove SHA512 option |
----|----|----|----
| Argon(0.8.0.-rc27) | 90308 | 76964 | 70884 |
| Photon(1.0.0) | 89492 | 76164 | 70100 |

exp.1) If application use TLS_RSA_WITH_AES_256_GCM_SHA256 certification only, developer could comment out the following ECC/SHA512 options from mbedtls/config.h for Flash spaces.
MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED,MBEDTLS_ASN1_WRITE_C,MBEDTLS_ECDH_C,MBEDTLS_ECDSA_C,MBEDTLS_ECP_C,MBEDTLS_SHA512_C

exp.2) Here is the default config.h and config-mini.h application size comparison with a1-example.cpp on Particle Photon firmware version 1.0.1 build VScode local compiler.

config.h

|text|data|bss|de|hex|filename|
----|----|----|----|----|----
|89492|168|11896|101556|18cb4|a1-example.elf|


config-mini.h

|text|data|bss|de|hex|filename|
----|----|----|----|----|----
|66868|148|11736|78752|133a0|a1-example.elf|

