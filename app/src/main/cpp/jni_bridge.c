/*
 * Traffic AL - on-device traffic audit for Android
 * Copyright (C) 2026 RudolfHK
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/* JNI glue between io.github.rudolfhk.traffical.vpn.NativeCapture and the capture engine. */

#include <jni.h>
#include <stdint.h>

#include "capture_engine.h"

typedef struct jni_ctx {
  JNIEnv *env;
  jobject obj;
  jmethodID resolve_uid;
  jmethodID on_packets;
  jmethodID protect;
} jni_ctx_t;

/* ******************************************************* */

static int clear_exception(JNIEnv *env) {
  if((*env)->ExceptionCheck(env)) {
    (*env)->ExceptionDescribe(env);
    (*env)->ExceptionClear(env);
    return 1;
  }
  return 0;
}

/* ******************************************************* */

static jbyteArray ip_to_bytes(JNIEnv *env, uint8_t ipver, const zdtun_ip_t *ip) {
  jsize len = (ipver == 4) ? 4 : 16;
  jbyteArray bytes = (*env)->NewByteArray(env, len);

  /* ip4 is stored in network byte order, so both variants are already big-endian bytes. */
  if(bytes)
    (*env)->SetByteArrayRegion(env, bytes, 0, len, (const jbyte*) ip);
  return bytes;
}

/* ******************************************************* */

static int jni_resolve_uid(void *userdata, const zdtun_5tuple_t *tuple) {
  jni_ctx_t *ctx = (jni_ctx_t*) userdata;
  JNIEnv *env = ctx->env;
  zdtun_ip_t src_ip, dst_ip;
  jbyteArray src, dst;
  jint uid = CAPTURE_UID_UNKNOWN;

  memcpy(&src_ip, &tuple->src_ip, sizeof(src_ip));
  memcpy(&dst_ip, &tuple->dst_ip, sizeof(dst_ip));
  src = ip_to_bytes(env, tuple->ipver, &src_ip);
  dst = ip_to_bytes(env, tuple->ipver, &dst_ip);

  if(src && dst) {
    uid = (*env)->CallIntMethod(env, ctx->obj, ctx->resolve_uid,
                                (jint) tuple->ipver, (jint) tuple->ipproto,
                                src, (jint) ntohs(tuple->src_port),
                                dst, (jint) ntohs(tuple->dst_port));
  }
  if(clear_exception(env))
    uid = CAPTURE_UID_UNKNOWN;

  if(src)
    (*env)->DeleteLocalRef(env, src);
  if(dst)
    (*env)->DeleteLocalRef(env, dst);
  return uid;
}

/* ******************************************************* */

static void jni_on_packets(void *userdata, const uint8_t *batch, size_t length) {
  jni_ctx_t *ctx = (jni_ctx_t*) userdata;
  JNIEnv *env = ctx->env;
  jbyteArray bytes = (*env)->NewByteArray(env, (jsize) length);

  if(bytes) {
    (*env)->SetByteArrayRegion(env, bytes, 0, (jsize) length, (const jbyte*) batch);
    (*env)->CallVoidMethod(env, ctx->obj, ctx->on_packets, bytes);
    (*env)->DeleteLocalRef(env, bytes);
  }
  clear_exception(env);
}

/* ******************************************************* */

static void jni_protect_socket(void *userdata, int sock) {
  jni_ctx_t *ctx = (jni_ctx_t*) userdata;

  (*ctx->env)->CallBooleanMethod(ctx->env, ctx->obj, ctx->protect, (jint) sock);
  clear_exception(ctx->env);
}

/* ******************************************************* */

#define ENGINE(handle) ((capture_engine_t*) (intptr_t) (handle))

JNIEXPORT jlong JNICALL
Java_io_github_rudolfhk_traffical_vpn_NativeCapture_nativeCreate(JNIEnv *env, jobject thiz) {
  return (jlong) (intptr_t) capture_engine_new();
}

JNIEXPORT void JNICALL
Java_io_github_rudolfhk_traffical_vpn_NativeCapture_nativeDestroy(JNIEnv *env, jobject thiz, jlong handle) {
  capture_engine_free(ENGINE(handle));
}

JNIEXPORT jboolean JNICALL
Java_io_github_rudolfhk_traffical_vpn_NativeCapture_nativeSetDns(JNIEnv *env, jobject thiz, jlong handle,
                                                                 jstring virtual_dns, jstring upstream_dns) {
  const char *virtual_str = (*env)->GetStringUTFChars(env, virtual_dns, NULL);
  const char *upstream_str = (*env)->GetStringUTFChars(env, upstream_dns, NULL);
  int rv = -1;

  if(virtual_str && upstream_str)
    rv = capture_engine_set_dns(ENGINE(handle), virtual_str, upstream_str);

  if(virtual_str)
    (*env)->ReleaseStringUTFChars(env, virtual_dns, virtual_str);
  if(upstream_str)
    (*env)->ReleaseStringUTFChars(env, upstream_dns, upstream_str);
  return (rv == 0) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL
Java_io_github_rudolfhk_traffical_vpn_NativeCapture_nativeSetBlockPrivateDns(JNIEnv *env, jobject thiz,
                                                                             jlong handle, jboolean block) {
  capture_engine_set_block_private_dns(ENGINE(handle), block ? 1 : 0);
}

JNIEXPORT jint JNICALL
Java_io_github_rudolfhk_traffical_vpn_NativeCapture_nativeRun(JNIEnv *env, jobject thiz, jlong handle,
                                                              jint tun_fd, jint mtu) {
  jclass cls = (*env)->GetObjectClass(env, thiz);
  jni_ctx_t ctx = {
    .env = env,
    .obj = thiz,
    .resolve_uid = (*env)->GetMethodID(env, cls, "resolveUid", "(II[BI[BI)I"),
    .on_packets = (*env)->GetMethodID(env, cls, "onPackets", "([B)V"),
    .protect = (*env)->GetMethodID(env, cls, "protect", "(I)Z"),
  };
  capture_callbacks_t callbacks = {
    .resolve_uid = jni_resolve_uid,
    .on_packets = jni_on_packets,
    .protect_socket = jni_protect_socket,
  };

  (*env)->DeleteLocalRef(env, cls);
  if(!ctx.resolve_uid || !ctx.on_packets || !ctx.protect) {
    clear_exception(env);
    return -1;
  }

  return capture_engine_run(ENGINE(handle), tun_fd, mtu, &callbacks, &ctx);
}

JNIEXPORT void JNICALL
Java_io_github_rudolfhk_traffical_vpn_NativeCapture_nativeStop(JNIEnv *env, jobject thiz, jlong handle) {
  capture_engine_stop(ENGINE(handle));
}
