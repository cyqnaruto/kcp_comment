//=====================================================================
//
// KCP - A Better ARQ Protocol Implementation
// skywind3000 (at) gmail.com, 2010-2011
//  
// Features:
// + Average RTT reduce 30% - 40% vs traditional ARQ like tcp.
// + Maximum RTT reduce three times vs tcp.
// + Lightweight, distributed as a single source file.
//
//=====================================================================
#include "ikcp.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>



//=====================================================================
// KCP BASIC
//=====================================================================
const IUINT32 IKCP_RTO_NDL = 30;		// no delay min rto
const IUINT32 IKCP_RTO_MIN = 100;		// normal min rto
const IUINT32 IKCP_RTO_DEF = 200;
const IUINT32 IKCP_RTO_MAX = 60000;
const IUINT32 IKCP_CMD_PUSH = 81;		// cmd: push data
const IUINT32 IKCP_CMD_ACK  = 82;		// cmd: ack
const IUINT32 IKCP_CMD_WASK = 83;		// cmd: window probe (ask)
const IUINT32 IKCP_CMD_WINS = 84;		// cmd: window size (tell)
const IUINT32 IKCP_ASK_SEND = 1;		// need to send IKCP_CMD_WASK
const IUINT32 IKCP_ASK_TELL = 2;		// need to send IKCP_CMD_WINS
const IUINT32 IKCP_WND_SND = 32;
const IUINT32 IKCP_WND_RCV = 128;       // must >= max fragment size
const IUINT32 IKCP_MTU_DEF = 1400;
const IUINT32 IKCP_ACK_FAST	= 3;
const IUINT32 IKCP_INTERVAL	= 100;
const IUINT32 IKCP_OVERHEAD = 24;
const IUINT32 IKCP_DEADLINK = 20;
const IUINT32 IKCP_THRESH_INIT = 2;
const IUINT32 IKCP_THRESH_MIN = 2;
const IUINT32 IKCP_PROBE_INIT = 7000;		// 7 secs to probe window size
const IUINT32 IKCP_PROBE_LIMIT = 120000;	// up to 120 secs to probe window
const IUINT32 IKCP_FASTACK_LIMIT = 5;		// max times to trigger fastack


//---------------------------------------------------------------------
// encode / decode
//---------------------------------------------------------------------

/* encode 8 bits unsigned int */
static inline char *ikcp_encode8u(char *p, unsigned char c)
{
	*(unsigned char*)p++ = c;
	return p;
}

/* decode 8 bits unsigned int */
static inline const char *ikcp_decode8u(const char *p, unsigned char *c)
{
	*c = *(unsigned char*)p++;
	return p;
}

/* encode 16 bits unsigned int (lsb) */
static inline char *ikcp_encode16u(char *p, unsigned short w)
{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
	*(unsigned char*)(p + 0) = (w & 255);
	*(unsigned char*)(p + 1) = (w >> 8);
#else
	memcpy(p, &w, 2);
#endif
	p += 2;
	return p;
}

/* decode 16 bits unsigned int (lsb) */
static inline const char *ikcp_decode16u(const char *p, unsigned short *w)
{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
	*w = *(const unsigned char*)(p + 1);
	*w = *(const unsigned char*)(p + 0) + (*w << 8);
#else
	memcpy(w, p, 2);
#endif
	p += 2;
	return p;
}

/* encode 32 bits unsigned int (lsb) */
static inline char *ikcp_encode32u(char *p, IUINT32 l)
{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
	*(unsigned char*)(p + 0) = (unsigned char)((l >>  0) & 0xff);
	*(unsigned char*)(p + 1) = (unsigned char)((l >>  8) & 0xff);
	*(unsigned char*)(p + 2) = (unsigned char)((l >> 16) & 0xff);
	*(unsigned char*)(p + 3) = (unsigned char)((l >> 24) & 0xff);
#else
	memcpy(p, &l, 4);
#endif
	p += 4;
	return p;
}

/* decode 32 bits unsigned int (lsb) */
static inline const char *ikcp_decode32u(const char *p, IUINT32 *l)
{
#if IWORDS_BIG_ENDIAN || IWORDS_MUST_ALIGN
	*l = *(const unsigned char*)(p + 3);
	*l = *(const unsigned char*)(p + 2) + (*l << 8);
	*l = *(const unsigned char*)(p + 1) + (*l << 8);
	*l = *(const unsigned char*)(p + 0) + (*l << 8);
#else 
	memcpy(l, p, 4);
#endif
	p += 4;
	return p;
}

static inline IUINT32 _imin_(IUINT32 a, IUINT32 b) {
	return a <= b ? a : b;
}

static inline IUINT32 _imax_(IUINT32 a, IUINT32 b) {
	return a >= b ? a : b;
}

static inline IUINT32 _ibound_(IUINT32 lower, IUINT32 middle, IUINT32 upper) 
{
	return _imin_(_imax_(lower, middle), upper);
}

static inline long _itimediff(IUINT32 later, IUINT32 earlier) 
{
	return ((IINT32)(later - earlier));
}

//---------------------------------------------------------------------
// manage segment
//---------------------------------------------------------------------
typedef struct IKCPSEG IKCPSEG;

static void* (*ikcp_malloc_hook)(size_t) = NULL;
static void (*ikcp_free_hook)(void *) = NULL;

// internal malloc
static void* ikcp_malloc(size_t size) {
	if (ikcp_malloc_hook) 
		return ikcp_malloc_hook(size);
	return malloc(size);
}

// internal free
static void ikcp_free(void *ptr) {
	if (ikcp_free_hook) {
		ikcp_free_hook(ptr);
	}	else {
		free(ptr);
	}
}

// redefine allocator
// comment: 自定义内存分配接口
void ikcp_allocator(void* (*new_malloc)(size_t), void (*new_free)(void*))
{
	ikcp_malloc_hook = new_malloc;
	ikcp_free_hook = new_free;
}

// allocate a new kcp segment
static IKCPSEG* ikcp_segment_new(ikcpcb *kcp, int size)
{
	return (IKCPSEG*)ikcp_malloc(sizeof(IKCPSEG) + size);
}

// delete a segment
static void ikcp_segment_delete(ikcpcb *kcp, IKCPSEG *seg)
{
	ikcp_free(seg);
}

// write log
// comment: log 接口
void ikcp_log(ikcpcb *kcp, int mask, const char *fmt, ...)
{
	char buffer[1024];
	va_list argptr;
	if ((mask & kcp->logmask) == 0 || kcp->writelog == 0) return;
	va_start(argptr, fmt);
	vsprintf(buffer, fmt, argptr);
	va_end(argptr);
	kcp->writelog(buffer, kcp, kcp->user);
}

// check log mask
static int ikcp_canlog(const ikcpcb *kcp, int mask)
{
	if ((mask & kcp->logmask) == 0 || kcp->writelog == NULL) return 0;
	return 1;
}

// output segment
static int ikcp_output(ikcpcb *kcp, const void *data, int size)
{
	assert(kcp);
	assert(kcp->output);
	if (ikcp_canlog(kcp, IKCP_LOG_OUTPUT)) {
		ikcp_log(kcp, IKCP_LOG_OUTPUT, "[RO] %ld bytes", (long)size);
	}
	if (size == 0) return 0;
	return kcp->output((const char*)data, size, kcp, kcp->user);
}

// output queue
void ikcp_qprint(const char *name, const struct IQUEUEHEAD *head)
{
#if 0
	const struct IQUEUEHEAD *p;
	printf("<%s>: [", name);
	for (p = head->next; p != head; p = p->next) {
		const IKCPSEG *seg = iqueue_entry(p, const IKCPSEG, node);
		printf("(%lu %d)", (unsigned long)seg->sn, (int)(seg->ts % 10000));
		if (p->next != head) printf(",");
	}
	printf("]\n");
#endif
}


//---------------------------------------------------------------------
// create a new kcpcb
//---------------------------------------------------------------------
// comment: 创建 kcp 控制结构体
ikcpcb* ikcp_create(IUINT32 conv, void *user)
{
	ikcpcb *kcp = (ikcpcb*)ikcp_malloc(sizeof(struct IKCPCB));
	if (kcp == NULL) return NULL;
	kcp->conv = conv;
	kcp->user = user;
	kcp->snd_una = 0;
	kcp->snd_nxt = 0;
	kcp->rcv_nxt = 0;
	kcp->ts_recent = 0;
	kcp->ts_lastack = 0;
	kcp->ts_probe = 0;
	kcp->probe_wait = 0;
	kcp->snd_wnd = IKCP_WND_SND;
	kcp->rcv_wnd = IKCP_WND_RCV;
	kcp->rmt_wnd = IKCP_WND_RCV;
	kcp->cwnd = 0;
	kcp->incr = 0;
	kcp->probe = 0;
	kcp->mtu = IKCP_MTU_DEF;
	kcp->mss = kcp->mtu - IKCP_OVERHEAD;
	kcp->stream = 0;

	kcp->buffer = (char*)ikcp_malloc((kcp->mtu + IKCP_OVERHEAD) * 3);
	if (kcp->buffer == NULL) {
		ikcp_free(kcp);
		return NULL;
	}

	iqueue_init(&kcp->snd_queue);
	iqueue_init(&kcp->rcv_queue);
	iqueue_init(&kcp->snd_buf);
	iqueue_init(&kcp->rcv_buf);
	kcp->nrcv_buf = 0;
	kcp->nsnd_buf = 0;
	kcp->nrcv_que = 0;
	kcp->nsnd_que = 0;
	kcp->state = 0;
	kcp->acklist = NULL;
	kcp->ackblock = 0;
	kcp->ackcount = 0;
	kcp->rx_srtt = 0;
	kcp->rx_rttval = 0;
	kcp->rx_rto = IKCP_RTO_DEF;
	kcp->rx_minrto = IKCP_RTO_MIN;
	kcp->current = 0;
	kcp->interval = IKCP_INTERVAL;
	kcp->ts_flush = IKCP_INTERVAL;
	kcp->nodelay = 0;
	kcp->updated = 0;
	kcp->logmask = 0;
	kcp->ssthresh = IKCP_THRESH_INIT;
	kcp->fastresend = 0;
	kcp->fastlimit = IKCP_FASTACK_LIMIT;
	kcp->nocwnd = 0;
	kcp->xmit = 0;
	kcp->dead_link = IKCP_DEADLINK;
	kcp->output = NULL;
	kcp->writelog = NULL;

	return kcp;
}


//---------------------------------------------------------------------
// release a new kcpcb
//---------------------------------------------------------------------
void ikcp_release(ikcpcb *kcp)
{
	assert(kcp);
	if (kcp) {
		IKCPSEG *seg;
		while (!iqueue_is_empty(&kcp->snd_buf)) {
			seg = iqueue_entry(kcp->snd_buf.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		while (!iqueue_is_empty(&kcp->rcv_buf)) {
			seg = iqueue_entry(kcp->rcv_buf.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		while (!iqueue_is_empty(&kcp->snd_queue)) {
			seg = iqueue_entry(kcp->snd_queue.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		while (!iqueue_is_empty(&kcp->rcv_queue)) {
			seg = iqueue_entry(kcp->rcv_queue.next, IKCPSEG, node);
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
		}
		if (kcp->buffer) {
			ikcp_free(kcp->buffer);
		}
		if (kcp->acklist) {
			ikcp_free(kcp->acklist);
		}

		kcp->nrcv_buf = 0;
		kcp->nsnd_buf = 0;
		kcp->nrcv_que = 0;
		kcp->nsnd_que = 0;
		kcp->ackcount = 0;
		kcp->buffer = NULL;
		kcp->acklist = NULL;
		ikcp_free(kcp);
	}
}


//---------------------------------------------------------------------
// set output callback, which will be invoked by kcp
//---------------------------------------------------------------------
// comment: 设置 kcp 的 output 函数指针
void ikcp_setoutput(ikcpcb *kcp, int (*output)(const char *buf, int len,
	ikcpcb *kcp, void *user))
{
	kcp->output = output;
}


//---------------------------------------------------------------------
// user/upper level recv: returns size, returns below zero for EAGAIN
//---------------------------------------------------------------------
// comment: 上层的 recv 函数（是已经 ack 过的 segment）
// comment: kcp - kcp 控制对象
// comment: buffer - 用于存储 kcp 中消息的 buffer
// comment: len - 想要从 kcp 中获取的字节数（小于 0 的 len 值代表 peek 操作）
// comment: return -1 - 接收队列为空
// comment: return -2 - 没有可以获取的消息
// comment: return -3 - len 小于 rcv_queue 中的消息长度，不允许获取部分
// comment: return > 0 - 获取到的消息长度
int ikcp_recv(ikcpcb *kcp, char *buffer, int len)
{
	struct IQUEUEHEAD *p;
    // comment: 是否是 peek 操作
	int ispeek = (len < 0)? 1 : 0;
	int peeksize;
    // comment: 是否需要快速恢复
	int recover = 0;
	IKCPSEG *seg;
	assert(kcp);

	if (iqueue_is_empty(&kcp->rcv_queue))
		return -1;

	if (len < 0) len = -len;

    // comment: 获取 kcp 的 recv_queue 中的消息长度
	peeksize = ikcp_peeksize(kcp);

	if (peeksize < 0) 
		return -2;

    // comment: 不允许获取部分消息
	if (peeksize > len) 
		return -3;

    // comment: 如果当前的 recv_queue 的长度大于了 recv_wnd 窗口大小
    // comment: 本轮消息获取完之后，可能需要快速恢复
	if (kcp->nrcv_que >= kcp->rcv_wnd)
		recover = 1;

	// merge fragment
	for (len = 0, p = kcp->rcv_queue.next; p != &kcp->rcv_queue; ) {
		int fragment;
		seg = iqueue_entry(p, IKCPSEG, node);
		p = p->next;

		if (buffer) {
			memcpy(buffer, seg->data, seg->len);
			buffer += seg->len;
		}

		len += seg->len;
		fragment = seg->frg;

		if (ikcp_canlog(kcp, IKCP_LOG_RECV)) {
			ikcp_log(kcp, IKCP_LOG_RECV, "recv sn=%lu", (unsigned long)seg->sn);
		}

        // comment: 如果不是 peek 操作，删除 segment
		if (ispeek == 0) {
			iqueue_del(&seg->node);
			ikcp_segment_delete(kcp, seg);
			kcp->nrcv_que--;
		}

        if (fragment == 0)
			break;
	}

    // comment: 最终获取的消息长度和之前预算的长度一致
	assert(len == peeksize);

    // comment: 将已经确认好的消息从 recv_buf 队列中移到 recv_queue 队列中
    // comment: 这里主要靠 segment 的 sn （segment 序号）和 kcp 中的 rev_nxt（下一个需要接收的 segment 序号）
	// move available data from rcv_buf -> rcv_queue
	while (! iqueue_is_empty(&kcp->rcv_buf)) {
		seg = iqueue_entry(kcp->rcv_buf.next, IKCPSEG, node);
        // comment: 序号确认 和 当前接收窗口没满
		if (seg->sn == kcp->rcv_nxt && kcp->nrcv_que < kcp->rcv_wnd) {
			iqueue_del(&seg->node);
			kcp->nrcv_buf--;
			iqueue_add_tail(&seg->node, &kcp->rcv_queue);
			kcp->nrcv_que++;
			kcp->rcv_nxt++;
		}	else {
			break;
		}
	}

    // comment: 接收窗口由满到不满，需要进行一次快速恢复，告诉对方自己当前的窗口大小
	// fast recover
	if (kcp->nrcv_que < kcp->rcv_wnd && recover) {
		// ready to send back IKCP_CMD_WINS in ikcp_flush
		// tell remote my window size
		kcp->probe |= IKCP_ASK_TELL;
	}

	return len;
}


//---------------------------------------------------------------------
// peek data size
//---------------------------------------------------------------------
// comment: recv queue 中下一个 message 的大小，以 frg == 0 为界限
// comment: 如果是 stream 类型，frg 都为 0，如果不是， frg == 0 的 segment 是最后一段 fragment
int ikcp_peeksize(const ikcpcb *kcp)
{
	struct IQUEUEHEAD *p;
	IKCPSEG *seg;
	int length = 0;

	assert(kcp);

	if (iqueue_is_empty(&kcp->rcv_queue)) return -1;

	seg = iqueue_entry(kcp->rcv_queue.next, IKCPSEG, node);
	if (seg->frg == 0) return seg->len;

	if (kcp->nrcv_que < seg->frg + 1) return -1;

	for (p = kcp->rcv_queue.next; p != &kcp->rcv_queue; p = p->next) {
		seg = iqueue_entry(p, IKCPSEG, node);
		length += seg->len;
		if (seg->frg == 0) break;
	}

	return length;
}


//---------------------------------------------------------------------
// user/upper level send, returns below zero for error
//---------------------------------------------------------------------
// comment: 上层的 send 函数
// comment: kcp - kcp 控制对象
// comment: buffer - 想要发送的消息 buffer
// comment: len - 想要发送的消息长度，len可以等于 0，可以发送空包
// comment: return -1 - len 大小错误，小于 0
// comment: return -2 - segment 创建失败
// comment: return  0 - 发送成功，数据成功加入 snd_queue
int ikcp_send(ikcpcb *kcp, const char *buffer, int len)
{
	IKCPSEG *seg;
	int count, i;

	assert(kcp->mss > 0);
    // comment: 发送长度小于 0，返回 -1
	if (len < 0) return -1;

	// append to previous segment in streaming mode (if possible)
    // comment: 流模式，可以粘包
	if (kcp->stream != 0) {
        // comment: 发送队列 snd_queue 不为空，尝试先将队尾的 segment 塞满
		if (!iqueue_is_empty(&kcp->snd_queue)) {
            // comment: old - 队尾的 segment
			IKCPSEG *old = iqueue_entry(kcp->snd_queue.prev, IKCPSEG, node);
            // comment: 队尾的 segment 没有达到 mss 大小，塞满
            if (old->len < kcp->mss) {
				int capacity = kcp->mss - old->len;
				int extend = (len < capacity)? len : capacity;
                // comment: 创建新的 segment
				seg = ikcp_segment_new(kcp, old->len + extend);
				assert(seg);
				if (seg == NULL) {
					return -2;
				}
				iqueue_add_tail(&seg->node, &kcp->snd_queue);
				memcpy(seg->data, old->data, old->len);
				if (buffer) {
					memcpy(seg->data + old->len, buffer, extend);
					buffer += extend;
				}
				seg->len = old->len + extend;
				seg->frg = 0;
				len -= extend;
                // comment: 删除旧的 segment
				iqueue_del_init(&old->node);
				ikcp_segment_delete(kcp, old);
			}
		}
        // comment: 如果 buffer 已经空了，返回
		if (len <= 0) {
			return 0;
		}
	}

    // comment: 剩下的 buffer 还需要多少个 segment
	if (len <= (int)kcp->mss) count = 1;
	else count = (len + kcp->mss - 1) / kcp->mss;

    // comment: 如果 segment 数量大于接收窗口大小，返回 -2
	if (count >= (int)IKCP_WND_RCV) return -2;

    // comment: 经过上面的计算，这里不可能等于 0 了吧，除非传进来的参数 len 就是 0
	if (count == 0) count = 1;

	// fragment
    // comment: 按照 mss 大小分段创建 segment
	for (i = 0; i < count; i++) {
		int size = len > (int)kcp->mss ? (int)kcp->mss : len;
		seg = ikcp_segment_new(kcp, size);
		assert(seg);
		if (seg == NULL) {
            // comment: ?? 这里 segment 创建失败的话，前面已经粘包的数据怎么办
			return -2;
		}
		if (buffer && len > 0) {
			memcpy(seg->data, buffer, size);
		}
		seg->len = size;
        // comment: 如果是流模式，不需要 fragment 序号，否则需要 fragment 序号
		seg->frg = (kcp->stream == 0)? (count - i - 1) : 0;
		iqueue_init(&seg->node);
		iqueue_add_tail(&seg->node, &kcp->snd_queue);
		kcp->nsnd_que++;
		if (buffer) {
			buffer += size;
		}
		len -= size;
	}

	return 0;
}


//---------------------------------------------------------------------
// parse ack
//---------------------------------------------------------------------
// comment: 对方发送包的 ack 更新，计算新的重传时间间隔 ??
static void ikcp_update_ack(ikcpcb *kcp, IINT32 rtt)
{
	IINT32 rto = 0;
	if (kcp->rx_srtt == 0) {
		kcp->rx_srtt = rtt;
		kcp->rx_rttval = rtt / 2;
	}	else {
		long delta = rtt - kcp->rx_srtt;
		if (delta < 0) delta = -delta;
		kcp->rx_rttval = (3 * kcp->rx_rttval + delta) / 4;
		kcp->rx_srtt = (7 * kcp->rx_srtt + rtt) / 8;
		if (kcp->rx_srtt < 1) kcp->rx_srtt = 1;
	}
	rto = kcp->rx_srtt + _imax_(kcp->interval, 4 * kcp->rx_rttval);
	kcp->rx_rto = _ibound_(kcp->rx_minrto, rto, IKCP_RTO_MAX);
}

// comment: 收缩 snd_buf
static void ikcp_shrink_buf(ikcpcb *kcp)
{
	struct IQUEUEHEAD *p = kcp->snd_buf.next;
    // comment: snd_buf 不为空，下一个需要确认的序号是 snd_buf 队头的 segment 的序号
	if (p != &kcp->snd_buf) {
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
		kcp->snd_una = seg->sn;
	}	else {
        // comment: snd_buf 已经空了，下一个需要确认的序号是下一个将要发送的序号
		kcp->snd_una = kcp->snd_nxt;
	}
}

// comment: 解析对方发送包的序号
static void ikcp_parse_ack(ikcpcb *kcp, IUINT32 sn)
{
	struct IQUEUEHEAD *p, *next;

    // comment: 不在需要确认的 ack 序号范围内，返回
	if (_itimediff(sn, kcp->snd_una) < 0 || _itimediff(sn, kcp->snd_nxt) >= 0)
		return;

    // comment: 从队头开始遍历 snd_buf，找到对应序号的 segment 并删除
	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = next) {
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
		next = p->next;
		if (sn == seg->sn) {
			iqueue_del(p);
			ikcp_segment_delete(kcp, seg);
			kcp->nsnd_buf--;
			break;
		}
		if (_itimediff(sn, seg->sn) < 0) {
			break;
		}
	}
}

// comment: 解析 ack，找出 snd_buf 中哪些 segment 已经被确认
static void ikcp_parse_una(ikcpcb *kcp, IUINT32 una)
{
	struct IQUEUEHEAD *p, *next;
    // comment: 从 snd_buf 队头开始
	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = next) {
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
		next = p->next;
        // comment: 当前未确认的 ack 大于 segment 的序号
        // comment: 即该 segment 已经被确认接收，删除
		if (_itimediff(una, seg->sn) > 0) {
			iqueue_del(p);
			ikcp_segment_delete(kcp, seg);
			kcp->nsnd_buf--;
		}	else {
			break;
		}
	}
}

// comment: 如果收到了单独的 ack 确认包，更新快速重传
static void ikcp_parse_fastack(ikcpcb *kcp, IUINT32 sn, IUINT32 ts)
{
	struct IQUEUEHEAD *p, *next;

    // comment: 不在需要确认的 ack 序号范围内，返回
	if (_itimediff(sn, kcp->snd_una) < 0 || _itimediff(sn, kcp->snd_nxt) >= 0)
		return;

    // comment: 从队头开始遍历 snd_buf，找到那些没有得到 ack 确认
    // comment: 并且序号小于 sn 的 segment，递增它们的 fastack 序号
	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = next) {
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
		next = p->next;
		if (_itimediff(sn, seg->sn) < 0) {
			break;
		}
		else if (sn != seg->sn) {
		#ifndef IKCP_FASTACK_CONSERVE
			seg->fastack++;
		#else
			if (_itimediff(ts, seg->ts) >= 0)
				seg->fastack++;
		#endif
		}
	}
}


//---------------------------------------------------------------------
// ack append
//---------------------------------------------------------------------
// comment: 记录收到的数据包的序号
static void ikcp_ack_push(ikcpcb *kcp, IUINT32 sn, IUINT32 ts)
{
	IUINT32 newsize = kcp->ackcount + 1;
	IUINT32 *ptr;

    // comment: 如果 ackblock 大小不够了，重新分配（resize）
	if (newsize > kcp->ackblock) {
		IUINT32 *acklist;
		IUINT32 newblock;

		for (newblock = 8; newblock < newsize; newblock <<= 1);
		acklist = (IUINT32*)ikcp_malloc(newblock * sizeof(IUINT32) * 2);

		if (acklist == NULL) {
			assert(acklist != NULL);
			abort();
		}

		if (kcp->acklist != NULL) {
			IUINT32 x;
			for (x = 0; x < kcp->ackcount; x++) {
				acklist[x * 2 + 0] = kcp->acklist[x * 2 + 0];
				acklist[x * 2 + 1] = kcp->acklist[x * 2 + 1];
			}
			ikcp_free(kcp->acklist);
		}

		kcp->acklist = acklist;
		kcp->ackblock = newblock;
	}

    // comment: (sn, ts) 放入 acklist 中
	ptr = &kcp->acklist[kcp->ackcount * 2];
	ptr[0] = sn;
	ptr[1] = ts;
    // comment: 递增 ackcount
	kcp->ackcount++;
}

static void ikcp_ack_get(const ikcpcb *kcp, int p, IUINT32 *sn, IUINT32 *ts)
{
	if (sn) sn[0] = kcp->acklist[p * 2 + 0];
	if (ts) ts[0] = kcp->acklist[p * 2 + 1];
}


//---------------------------------------------------------------------
// parse data
//---------------------------------------------------------------------
// comment: 名字叫解析数据，实际上是做的 ack 确认
void ikcp_parse_data(ikcpcb *kcp, IKCPSEG *newseg)
{
	struct IQUEUEHEAD *p, *prev;
	IUINT32 sn = newseg->sn;
	int repeat = 0;
	
    // comment: ack 序号在接收窗口之外，删除
	if (_itimediff(sn, kcp->rcv_nxt + kcp->rcv_wnd) >= 0 ||
		_itimediff(sn, kcp->rcv_nxt) < 0) {
		ikcp_segment_delete(kcp, newseg);
		return;
	}

    // comment: 遍历 rcv_buf 队列，从队尾向队头，大 ack 向小 ack
	for (p = kcp->rcv_buf.prev; p != &kcp->rcv_buf; p = prev) {
		IKCPSEG *seg = iqueue_entry(p, IKCPSEG, node);
		prev = p->prev;
        // comment: 如果该包已经接收过了，置 repeat 标志
		if (seg->sn == sn) {
			repeat = 1;
			break;
		}
        // comment: 是没有收到过的 ack，break
        // comment: 此时，p 指针指向新 segment 应该插入的位置之前
		if (_itimediff(sn, seg->sn) > 0) {
			break;
		}
	}

    // comment: 是没有收到过的 ack，插入 rcv_buf
	if (repeat == 0) {
		iqueue_init(&newseg->node);
        // comment: 插入在队列 p 指针位置之后
		iqueue_add(&newseg->node, p);
        // comment: 接收队列长度 +1
		kcp->nrcv_buf++;
	}	else {
        // comment: ack 重复，删除 segment
		ikcp_segment_delete(kcp, newseg);
	}

#if 0
	ikcp_qprint("rcvbuf", &kcp->rcv_buf);
	printf("rcv_nxt=%lu\n", kcp->rcv_nxt);
#endif

	// move available data from rcv_buf -> rcv_queue
    // comment: 将已经连续确认 ack 的 segment 从 rcv_buf 移到 rcv_queue
	while (! iqueue_is_empty(&kcp->rcv_buf)) {
        // comment: 遍历 rcv_buf，从队头向队尾
		IKCPSEG *seg = iqueue_entry(kcp->rcv_buf.next, IKCPSEG, node);
        // comment: 队头的 ack 序号是下一个要接收的 ack 序号，并且接收窗口没有满
		if (seg->sn == kcp->rcv_nxt && kcp->nrcv_que < kcp->rcv_wnd) {
            // comment: 从 rcv_buf 中删除
			iqueue_del(&seg->node);
			kcp->nrcv_buf--;
            // comment: 插入 rcv_queue 队尾
			iqueue_add_tail(&seg->node, &kcp->rcv_queue);
			kcp->nrcv_que++;
			kcp->rcv_nxt++;
		}	else {
			break;
		}
	}

#if 0
	ikcp_qprint("queue", &kcp->rcv_queue);
	printf("rcv_nxt=%lu\n", kcp->rcv_nxt);
#endif

#if 1
//	printf("snd(buf=%d, queue=%d)\n", kcp->nsnd_buf, kcp->nsnd_que);
//	printf("rcv(buf=%d, queue=%d)\n", kcp->nrcv_buf, kcp->nrcv_que);
#endif
}


//---------------------------------------------------------------------
// input data
//---------------------------------------------------------------------
// comment: 接收到元数据
int ikcp_input(ikcpcb *kcp, const char *data, long size)
{
    // comment: 解析数据之前还未得到 ack 确认的序号
	IUINT32 prev_una = kcp->snd_una;
	IUINT32 maxack = 0, latest_ts = 0;
	int flag = 0;

	if (ikcp_canlog(kcp, IKCP_LOG_INPUT)) {
		ikcp_log(kcp, IKCP_LOG_INPUT, "[RI] %d bytes", (int)size);
	}

    // comment: 底层读取的数据无效，指针无效 或 长度不够 segment 包头长度
	if (data == NULL || (int)size < (int)IKCP_OVERHEAD) return -1;

    // comment: 循环解析数据包
	while (1) {
		IUINT32 ts, sn, len, una, conv;
		IUINT16 wnd;
		IUINT8 cmd, frg;
		IKCPSEG *seg;

        // comment: 当前数据长度已经不够包头长度，跳出
		if (size < (int)IKCP_OVERHEAD) break;

        // comment: 开始解析包头
        // comment: 解析会话编号
		data = ikcp_decode32u(data, &conv);
        // comment: 会话编号不一致，出错
		if (conv != kcp->conv) return -1;

        // comment: 包体类型
		data = ikcp_decode8u(data, &cmd);
        // comment: fragment 段号
		data = ikcp_decode8u(data, &frg);
        // comment: 对方接收窗口大小
		data = ikcp_decode16u(data, &wnd);
        // comment: 发送时间戳
		data = ikcp_decode32u(data, &ts);
        // comment: 数据包序号
		data = ikcp_decode32u(data, &sn);
		data = ikcp_decode32u(data, &una);
        // comment: 数据长度
		data = ikcp_decode32u(data, &len);

        // comment: 减去已经解析完的包头长度
		size -= IKCP_OVERHEAD;

        // comment: 如果剩余长度，不足包体数据长度，出错
		if ((long)size < (long)len || (int)len < 0) return -2;

        // comment:无效的包体类型
		if (cmd != IKCP_CMD_PUSH && cmd != IKCP_CMD_ACK &&
			cmd != IKCP_CMD_WASK && cmd != IKCP_CMD_WINS) 
			return -3;

        // comment: 置对方当前接收窗口大小
		kcp->rmt_wnd = wnd;
        // comment: 己方已发送包 ack 确认，删除 snd_buf 中已经得到确认的 segment
		ikcp_parse_una(kcp, una);
		ikcp_shrink_buf(kcp);

        // comment: 单独的 ack 包
		if (cmd == IKCP_CMD_ACK) {
            // comment: 对方发送包的 ack 更新，计算新的重传时间间隔
			if (_itimediff(kcp->current, ts) >= 0) {
				ikcp_update_ack(kcp, _itimediff(kcp->current, ts));
			}
            // comment: 解析对方发送包的序号
            // comment: 这是单独的 ack 包，sn 表示的是确认的包序号
			ikcp_parse_ack(kcp, sn);
			ikcp_shrink_buf(kcp);
            // comment: 置直接收到 ack 确认的标记
            // comment: 并记录收到的最大的 ack 序号及对应时间戳
			if (flag == 0) {
				flag = 1;
				maxack = sn;
				latest_ts = ts;
			}	else {
				if (_itimediff(sn, maxack) > 0) {
				#ifndef IKCP_FASTACK_CONSERVE
					maxack = sn;
					latest_ts = ts;
				#else
					if (_itimediff(ts, latest_ts) > 0) {
						maxack = sn;
						latest_ts = ts;
					}
				#endif
				}
			}
			if (ikcp_canlog(kcp, IKCP_LOG_IN_ACK)) {
				ikcp_log(kcp, IKCP_LOG_IN_ACK, 
					"input ack: sn=%lu rtt=%ld rto=%ld", (unsigned long)sn, 
					(long)_itimediff(kcp->current, ts),
					(long)kcp->rx_rto);
			}
		}
        // comment: 数据包
		else if (cmd == IKCP_CMD_PUSH) {
			if (ikcp_canlog(kcp, IKCP_LOG_IN_DATA)) {
				ikcp_log(kcp, IKCP_LOG_IN_DATA, 
					"input psh: sn=%lu ts=%lu", (unsigned long)sn, (unsigned long)ts);
			}
            // comment: 如果数据包的 ack 序号在接收窗口范围内，接收
			if (_itimediff(sn, kcp->rcv_nxt + kcp->rcv_wnd) < 0) {
                // comment: 记录收到的数据包的序号
				ikcp_ack_push(kcp, sn, ts);
                // comment: 数据包 ack 序号 >= 下一个要接收的 ack 序号
				if (_itimediff(sn, kcp->rcv_nxt) >= 0) {
                    // comment: 创建新的 segment
					seg = ikcp_segment_new(kcp, len);
					seg->conv = conv;
					seg->cmd = cmd;
					seg->frg = frg;
					seg->wnd = wnd;
					seg->ts = ts;
					seg->sn = sn;
					seg->una = una;
					seg->len = len;

                    // comment: 拷贝数据
					if (len > 0) {
						memcpy(seg->data, data, len);
					}

					ikcp_parse_data(kcp, seg);
				}
			}
		}
        // comment: 查询接收窗口
		else if (cmd == IKCP_CMD_WASK) {
			// ready to send back IKCP_CMD_WINS in ikcp_flush
			// tell remote my window size
            // comment: 在下次 flush 时将自己的接收窗口大小发送给对方
			kcp->probe |= IKCP_ASK_TELL;
			if (ikcp_canlog(kcp, IKCP_LOG_IN_PROBE)) {
				ikcp_log(kcp, IKCP_LOG_IN_PROBE, "input probe");
			}
		}
        // comment: 己方查询对方接收窗口大小的反馈
        // comment: 已经在上面赋值，所以这里不做事
		else if (cmd == IKCP_CMD_WINS) {
			// do nothing
			if (ikcp_canlog(kcp, IKCP_LOG_IN_WINS)) {
				ikcp_log(kcp, IKCP_LOG_IN_WINS,
					"input wins: %lu", (unsigned long)(wnd));
			}
		}
		else {
			return -3;
		}

		data += len;
		size -= len;
	}

    // comment: 如果收到了单独的 ack 确认包，更新快速重传 ack 计数
	if (flag != 0) {
		ikcp_parse_fastack(kcp, maxack, latest_ts);
	}

    // comment: 如果未确认的 segment 序号得到更新
	if (_itimediff(kcp->snd_una, prev_una) > 0) {
		if (kcp->cwnd < kcp->rmt_wnd) {
			IUINT32 mss = kcp->mss;
			if (kcp->cwnd < kcp->ssthresh) {
				kcp->cwnd++;
				kcp->incr += mss;
			}	else {
				if (kcp->incr < mss) kcp->incr = mss;
				kcp->incr += (mss * mss) / kcp->incr + (mss / 16);
				if ((kcp->cwnd + 1) * mss <= kcp->incr) {
				#if 1
					kcp->cwnd = (kcp->incr + mss - 1) / ((mss > 0)? mss : 1);
				#else
					kcp->cwnd++;
				#endif
				}
			}
            // comment: 发送窗口上限 不能大于对方接收窗口大小
			if (kcp->cwnd > kcp->rmt_wnd) {
				kcp->cwnd = kcp->rmt_wnd;
				kcp->incr = kcp->rmt_wnd * mss;
			}
		}
	}

	return 0;
}


//---------------------------------------------------------------------
// ikcp_encode_seg
//---------------------------------------------------------------------
// comment: 将 seg 内容编码至 ptr 指向的 buffer 中
static char *ikcp_encode_seg(char *ptr, const IKCPSEG *seg)
{
	ptr = ikcp_encode32u(ptr, seg->conv);
	ptr = ikcp_encode8u(ptr, (IUINT8)seg->cmd);
	ptr = ikcp_encode8u(ptr, (IUINT8)seg->frg);
	ptr = ikcp_encode16u(ptr, (IUINT16)seg->wnd);
	ptr = ikcp_encode32u(ptr, seg->ts);
	ptr = ikcp_encode32u(ptr, seg->sn);
	ptr = ikcp_encode32u(ptr, seg->una);
	ptr = ikcp_encode32u(ptr, seg->len);
	return ptr;
}

// comment: 当前接收窗口剩余的大小
static int ikcp_wnd_unused(const ikcpcb *kcp)
{
	if (kcp->nrcv_que < kcp->rcv_wnd) {
		return kcp->rcv_wnd - kcp->nrcv_que;
	}
	return 0;
}


//---------------------------------------------------------------------
// ikcp_flush
//---------------------------------------------------------------------
// comment: 发送数据，处理 ack 确认、查询发送窗口、快速重传、超时重传等
void ikcp_flush(ikcpcb *kcp)
{
	IUINT32 current = kcp->current;
    // comment: 底层的发送 buffer，segment 内容编码后 copy 到 buffer 中
    char *buffer = kcp->buffer;
    // comment: buffer 默认为空
	char *ptr = buffer;
	int count, size, i;
	IUINT32 resent, cwnd;
	IUINT32 rtomin;
	struct IQUEUEHEAD *p;
	int change = 0;
	int lost = 0;
	IKCPSEG seg;

	// 'ikcp_update' haven't been called. 
	if (kcp->updated == 0) return;

    // comment: 置基本信息
	seg.conv = kcp->conv;
	seg.cmd = IKCP_CMD_ACK;
	seg.frg = 0;
	seg.wnd = ikcp_wnd_unused(kcp);
	seg.una = kcp->rcv_nxt;
	seg.len = 0;
	seg.sn = 0;
	seg.ts = 0;

	// flush acknowledges
    // comment: 发送接收确认 ack
	count = kcp->ackcount;
	for (i = 0; i < count; i++) {
		size = (int)(ptr - buffer);
		if (size + (int)IKCP_OVERHEAD > (int)kcp->mtu) {
			ikcp_output(kcp, buffer, size);
			ptr = buffer;
		}
		ikcp_ack_get(kcp, i, &seg.sn, &seg.ts);
		ptr = ikcp_encode_seg(ptr, &seg);
	}

	kcp->ackcount = 0;

	// probe window size (if remote window size equals zero)
    // comment: 上一轮接收中，对方的接收窗口置为 0，需要定时查询对方的接收窗口大小
	if (kcp->rmt_wnd == 0) {
        // comment: 没有在查询定时中，置查询定时为 IKCP_PROBE_INIT（7s） 时间后
		if (kcp->probe_wait == 0) {
			kcp->probe_wait = IKCP_PROBE_INIT;
			kcp->ts_probe = kcp->current + kcp->probe_wait;
        }
        // comment: 已经在 probe 定时中
		else {
            // comment: 到达 probe 定时时间点
			if (_itimediff(kcp->current, kcp->ts_probe) >= 0) {
				if (kcp->probe_wait < IKCP_PROBE_INIT) 
					kcp->probe_wait = IKCP_PROBE_INIT;
				kcp->probe_wait += kcp->probe_wait / 2;
				if (kcp->probe_wait > IKCP_PROBE_LIMIT)
					kcp->probe_wait = IKCP_PROBE_LIMIT;
                // comment: 置下一次查询时间点
				kcp->ts_probe = kcp->current + kcp->probe_wait;
                // comment: 置 probe 标记
				kcp->probe |= IKCP_ASK_SEND;
			}
		}
	}	else {
		kcp->ts_probe = 0;
		kcp->probe_wait = 0;
	}

	// flush window probing commands
    // comment: 如果有查询请求，发送
	if (kcp->probe & IKCP_ASK_SEND) {
        // comment: cmd 类型为 IKCP_CMD_WASK，接收窗口查询
		seg.cmd = IKCP_CMD_WASK;
		size = (int)(ptr - buffer);
		if (size + (int)IKCP_OVERHEAD > (int)kcp->mtu) {
			ikcp_output(kcp, buffer, size);
			ptr = buffer;
		}
		ptr = ikcp_encode_seg(ptr, &seg);
	}

	// flush window probing commands
    // comment: 如果对方查询发送窗口大小，发送
	if (kcp->probe & IKCP_ASK_TELL) {
        // comment: cmd 类型为 IKCP_CMD_WINS，发送自己的接收窗口大小
		seg.cmd = IKCP_CMD_WINS;
		size = (int)(ptr - buffer);
		if (size + (int)IKCP_OVERHEAD > (int)kcp->mtu) {
			ikcp_output(kcp, buffer, size);
			ptr = buffer;
		}
		ptr = ikcp_encode_seg(ptr, &seg);
	}

    // comment: 置空 probe 标志
	kcp->probe = 0;

	// calculate window size
    // comment: 下面开始发送实际数据，需要关注自己发送窗口大小和对方接收窗口大小
	cwnd = _imin_(kcp->snd_wnd, kcp->rmt_wnd);
    // comment: 发送窗口限制（当发生快速重传和丢包时，会加入发送窗口限制）
	if (kcp->nocwnd == 0) cwnd = _imin_(kcp->cwnd, cwnd);

	// move data from snd_queue to snd_buf
    // comment: 当前发送序号在发送窗口范围内
	while (_itimediff(kcp->snd_nxt, kcp->snd_una + cwnd) < 0) {
		IKCPSEG *newseg;
		if (iqueue_is_empty(&kcp->snd_queue)) break;

        // comment: snd_queue 队头的 segment
		newseg = iqueue_entry(kcp->snd_queue.next, IKCPSEG, node);

        // comment: 从 snd_queue 中删除
		iqueue_del(&newseg->node);
        // comment: 加入 snd_buf
		iqueue_add_tail(&newseg->node, &kcp->snd_buf);
		kcp->nsnd_que--;
		kcp->nsnd_buf++;

		newseg->conv = kcp->conv;
		newseg->cmd = IKCP_CMD_PUSH;
		newseg->wnd = seg.wnd;
		newseg->ts = current;
        // comment: 递增发送序号
		newseg->sn = kcp->snd_nxt++;
        // comment: 下一个要接收的包序号，该序号之前的包都已经收到，即 ack
        newseg->una = kcp ->rcv_nxt;
        // comment: 重传时间
		newseg->resendts = current;
		newseg->rto = kcp->rx_rto;
		newseg->fastack = 0;
		newseg->xmit = 0;
	}

	// calculate resent
    // comment: 快速重传
	resent = (kcp->fastresend > 0)? (IUINT32)kcp->fastresend : 0xffffffff;
    // comment: 重传延时
	rtomin = (kcp->nodelay == 0)? (kcp->rx_rto >> 3) : 0;

	// flush data segments
    // comment: 发送数据包，从 snd_buf 队头开始
	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = p->next) {
		IKCPSEG *segment = iqueue_entry(p, IKCPSEG, node);
        // comment: 这个包是否需要发送
		int needsend = 0;
        // comment: 第一次发送，直接发送
		if (segment->xmit == 0) {
			needsend = 1;
            // comment: 包的重传计数
			segment->xmit++;
            // comment: 置重传间隔
			segment->rto = kcp->rx_rto;
            // comment: 置下一次重传时间点
			segment->resendts = current + segment->rto + rtomin;
		}
        // comment: 到了包的重传时间点，重新发送
		else if (_itimediff(current, segment->resendts) >= 0) {
			needsend = 1;
            // comment: 包的重传计数
			segment->xmit++;
            // comment: 会话重传计数
			kcp->xmit++;
            // comment:
			if (kcp->nodelay == 0) {
				segment->rto += _imax_(segment->rto, (IUINT32)kcp->rx_rto);
			}	else {
				IINT32 step = (kcp->nodelay < 2)? 
					((IINT32)(segment->rto)) : kcp->rx_rto;
				segment->rto += step / 2;
			}
			segment->resendts = current + segment->rto;
			lost = 1;
		}
        // comment: 快速重传
		else if (segment->fastack >= resent) {
            // comment: 重传次数小于快速重传次数限制 或 没有快速重传次数限制
			if ((int)segment->xmit <= kcp->fastlimit || 
				kcp->fastlimit <= 0) {
				needsend = 1;
                // comment: 包的重传计数
				segment->xmit++;
				segment->fastack = 0;
				segment->resendts = current + segment->rto;
				change++;
			}
		}

        // comment: 如果需要发送，发送
		if (needsend) {
			int need;
			segment->ts = current;
			segment->wnd = seg.wnd;
			segment->una = kcp->rcv_nxt;

			size = (int)(ptr - buffer);
			need = IKCP_OVERHEAD + segment->len;

            // comment: 如果 buffer 数据加上包的数据长度大于 mtu，
            // comment: 先把 buffer 中的数据发送完，保证单次
            // comment: 发送包大小不会大于 mtu
			if (size + need > (int)kcp->mtu) {
				ikcp_output(kcp, buffer, size);
				ptr = buffer;
			}

            // comment: 编码 segment 及 数据段
			ptr = ikcp_encode_seg(ptr, segment);

			if (segment->len > 0) {
				memcpy(ptr, segment->data, segment->len);
				ptr += segment->len;
			}

            // comment: 如果重传次数大于连接断开重传计数，设置会话状态
			if (segment->xmit >= kcp->dead_link) {
				kcp->state = (IUINT32)-1;
			}
		}
	}

	// flash remain segments
    // comment: 发送完 buffer 中剩余的数据，所以每次 flush 后 buffer 是空的
	size = (int)(ptr - buffer);
	if (size > 0) {
		ikcp_output(kcp, buffer, size);
	}

	// update ssthresh
    // comment: 发生快速重传，限制发送
	if (change) {
		IUINT32 inflight = kcp->snd_nxt - kcp->snd_una;
		kcp->ssthresh = inflight / 2;
		if (kcp->ssthresh < IKCP_THRESH_MIN)
			kcp->ssthresh = IKCP_THRESH_MIN;
		kcp->cwnd = kcp->ssthresh + resent;
		kcp->incr = kcp->cwnd * kcp->mss;
	}

    // comment: 发生丢包，限制发送
	if (lost) {
		kcp->ssthresh = cwnd / 2;
		if (kcp->ssthresh < IKCP_THRESH_MIN)
			kcp->ssthresh = IKCP_THRESH_MIN;
		kcp->cwnd = 1;
		kcp->incr = kcp->mss;
	}

	if (kcp->cwnd < 1) {
		kcp->cwnd = 1;
		kcp->incr = kcp->mss;
	}
}


//---------------------------------------------------------------------
// update state (call it repeatedly, every 10ms-100ms), or you can ask 
// ikcp_check when to call it again (without ikcp_input/_send calling).
// 'current' - current timestamp in millisec. 
//---------------------------------------------------------------------
void ikcp_update(ikcpcb *kcp, IUINT32 current)
{
	IINT32 slap;

	kcp->current = current;

	if (kcp->updated == 0) {
		kcp->updated = 1;
		kcp->ts_flush = kcp->current;
	}

	slap = _itimediff(kcp->current, kcp->ts_flush);

	if (slap >= 10000 || slap < -10000) {
		kcp->ts_flush = kcp->current;
		slap = 0;
	}

	if (slap >= 0) {
		kcp->ts_flush += kcp->interval;
		if (_itimediff(kcp->current, kcp->ts_flush) >= 0) {
			kcp->ts_flush = kcp->current + kcp->interval;
		}
		ikcp_flush(kcp);
	}
}


//---------------------------------------------------------------------
// Determine when should you invoke ikcp_update:
// returns when you should invoke ikcp_update in millisec, if there 
// is no ikcp_input/_send calling. you can call ikcp_update in that
// time, instead of call update repeatly.
// Important to reduce unnacessary ikcp_update invoking. use it to 
// schedule ikcp_update (eg. implementing an epoll-like mechanism, 
// or optimize ikcp_update when handling massive kcp connections)
//---------------------------------------------------------------------
IUINT32 ikcp_check(const ikcpcb *kcp, IUINT32 current)
{
	IUINT32 ts_flush = kcp->ts_flush;
	IINT32 tm_flush = 0x7fffffff;
	IINT32 tm_packet = 0x7fffffff;
	IUINT32 minimal = 0;
	struct IQUEUEHEAD *p;

	if (kcp->updated == 0) {
		return current;
	}

	if (_itimediff(current, ts_flush) >= 10000 ||
		_itimediff(current, ts_flush) < -10000) {
		ts_flush = current;
	}

	if (_itimediff(current, ts_flush) >= 0) {
		return current;
	}

	tm_flush = _itimediff(ts_flush, current);

	for (p = kcp->snd_buf.next; p != &kcp->snd_buf; p = p->next) {
		const IKCPSEG *seg = iqueue_entry(p, const IKCPSEG, node);
		IINT32 diff = _itimediff(seg->resendts, current);
		if (diff <= 0) {
			return current;
		}
		if (diff < tm_packet) tm_packet = diff;
	}

	minimal = (IUINT32)(tm_packet < tm_flush ? tm_packet : tm_flush);
	if (minimal >= kcp->interval) minimal = kcp->interval;

	return current + minimal;
}


// comment: 设置 mtu 大小
// comment: return -1 - 新的 mtu 大小过小
// comment: return -2 - 新的 buffer 创建失败
// comment: return  0 - 设置成功
int ikcp_setmtu(ikcpcb *kcp, int mtu)
{
	char *buffer;
	if (mtu < 50 || mtu < (int)IKCP_OVERHEAD) 
		return -1;
    // comment: 创建新的 buffer，大小??
	buffer = (char*)ikcp_malloc((mtu + IKCP_OVERHEAD) * 3);
	if (buffer == NULL) 
		return -2;
	kcp->mtu = mtu;
    // comment: mss 最大报文大小 = mtu 最大传输单元大小 - 链路层负载
	kcp->mss = kcp->mtu - IKCP_OVERHEAD;
	ikcp_free(kcp->buffer);
	kcp->buffer = buffer;
	return 0;
}

// comment: 设置 kcp update 间隔
int ikcp_interval(ikcpcb *kcp, int interval)
{
	if (interval > 5000) interval = 5000;
	else if (interval < 10) interval = 10;
	kcp->interval = interval;
	return 0;
}

// comment: 设置 kcp 性能控制参数
// comment: nodelay - 重传延时，0 - 关闭（默认），1 - 打开
// comment: interval - update 间隔
// comment: resend - 快速重传，0 - 关闭（默认），1 - 打开
// comment: nc - 拥塞控制，0 - 打开（默认），1 - 关闭
int ikcp_nodelay(ikcpcb *kcp, int nodelay, int interval, int resend, int nc)
{
    // comment: nodelay 重传延迟
	if (nodelay >= 0) {
		kcp->nodelay = nodelay;
        // comment: 设置了 nodelay，则重传最小时间为 IKCP_RTO_NDL
		if (nodelay) {
			kcp->rx_minrto = IKCP_RTO_NDL;	
        }
        // comment: 否则为 IKCP_RTO_MIN
		else {
			kcp->rx_minrto = IKCP_RTO_MIN;
		}
	}
    // comment: update 间隔
	if (interval >= 0) {
		if (interval > 5000) interval = 5000;
		else if (interval < 10) interval = 10;
		kcp->interval = interval;
	}
    // comment: 快速重传标志
	if (resend >= 0) {
		kcp->fastresend = resend;
	}
    // comment: 拥塞控制（发送窗口控制）
	if (nc >= 0) {
		kcp->nocwnd = nc;
	}
	return 0;
}

// comment: 设置发送窗口和接收窗口大小
int ikcp_wndsize(ikcpcb *kcp, int sndwnd, int rcvwnd)
{
	if (kcp) {
		if (sndwnd > 0) {
			kcp->snd_wnd = sndwnd;
		}
		if (rcvwnd > 0) {   // must >= max fragment size
            // comment: 确保接收窗口不小于 IKCP_WND_RCV
			kcp->rcv_wnd = _imax_(rcvwnd, IKCP_WND_RCV);
		}
	}
	return 0;
}

// comment: 还有多少包等待发送，snd_buf 大小 + snd_queue 大小
int ikcp_waitsnd(const ikcpcb *kcp)
{
	return kcp->nsnd_buf + kcp->nsnd_que;
}


// read conv
// comment: 从数据包中解析出 会话编号 conv
IUINT32 ikcp_getconv(const void *ptr)
{
	IUINT32 conv;
	ikcp_decode32u((const char*)ptr, &conv);
	return conv;
}


