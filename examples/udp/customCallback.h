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
#ifndef WS2_32$htons
DECLSPEC_IMPORT u_short WSAAPI WS2_32$htons(u_short);
#endif
#ifndef WS2_32$inet_addr
DECLSPEC_IMPORT unsigned long WSAAPI WS2_32$inet_addr(const char *cp);
#endif

#define BROKER_TIMEOUT_MS 5000
#define MAX_DATAGRAM_SIZE 65535

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

    DWORD packetLen = sizeof(DWORD) + reqLen;
    char *packet = (char *)KERNEL32$HeapAlloc(hHeap, 0, packetLen);
    if (packet == NULL) {
        MSVCRT$printf("[customCallback] allocation failed for request packet\n");
        goto cleanup;
    }

    memcpy(packet, &reqLen, sizeof(DWORD));
    memcpy(packet + sizeof(DWORD), encodedRequest, reqLen);

    int sent = WS2_32$send(sock, packet, (int)packetLen, 0);
    KERNEL32$HeapFree(hHeap, 0, packet);
    if (sent != (int)packetLen) {
        MSVCRT$printf("[customCallback] failed to send request packet over UDP\n");
        goto cleanup;
    }

    recvBuf = (char *)KERNEL32$HeapAlloc(hHeap, 0, MAX_DATAGRAM_SIZE);
    if (recvBuf == NULL) {
        MSVCRT$printf("[customCallback] allocation failed for receive buffer\n");
        goto cleanup;
    }

    int received = WS2_32$recv(sock, recvBuf, MAX_DATAGRAM_SIZE, 0);
    if (received < (int)sizeof(DWORD)) {
        MSVCRT$printf("[customCallback] failed to receive response length over UDP\n");
        goto cleanup;
    }

    DWORD responseLen = 0;
    memcpy(&responseLen, recvBuf, sizeof(DWORD));

    if (responseLen == 0 || responseLen > (DWORD)(received - sizeof(DWORD))) {
        MSVCRT$printf("[customCallback] invalid response length in UDP packet\n");
        goto cleanup;
    }

    responseBuf = (char *)KERNEL32$HeapAlloc(hHeap, 0, responseLen + 1);
    if (responseBuf == NULL) {
        MSVCRT$printf("[customCallback] allocation failed for response buffer\n");
        goto cleanup;
    }

    memcpy(responseBuf, recvBuf + sizeof(DWORD), responseLen);
    responseBuf[responseLen] = '\0';

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
