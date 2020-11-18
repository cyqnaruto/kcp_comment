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
#ifndef __IKCP_H__
#define __IKCP_H__

#include <stddef.h>
#include <stdlib.h>
#include <assert.h>

// comment: 统一各平台下 32位 uint 和 int 类型定义
//=====================================================================
// 32BIT INTEGER DEFINITION 
//=====================================================================
#ifndef __INTEGER_32_BITS__
#define __INTEGER_32_BITS__
#if defined(_WIN64) || defined(WIN64) || defined(__amd64__) || \
	defined(__x86_64) || defined(__x86_64__) || defined(_M_IA64) || \
	defined(_M_AMD64)
	typedef unsigned int ISTDUINT32;
	typedef int ISTDINT32;
#elif defined(_WIN32) || defined(WIN32) || defined(__i386__) || \
	defined(__i386) || defined(_M_X86)
	typedef unsigned long ISTDUINT32;
	typedef long ISTDINT32;
#elif defined(__MACOS__)
	typedef UInt32 ISTDUINT32;
	typedef SInt32 ISTDINT32;
#elif defined(__APPLE__) && defined(__MACH__)
	#include <sys/types.h>
	typedef u_int32_t ISTDUINT32;
	typedef int32_t ISTDINT32;
#elif defined(__BEOS__)
	#include <sys/inttypes.h>
	typedef u_int32_t ISTDUINT32;
	typedef int32_t ISTDINT32;
#elif (defined(_MSC_VER) || defined(__BORLANDC__)) && (!defined(__MSDOS__))
	typedef unsigned __int32 ISTDUINT32;
	typedef __int32 ISTDINT32;
#elif defined(__GNUC__)
	#include <stdint.h>
	typedef uint32_t ISTDUINT32;
	typedef int32_t ISTDINT32;
#else 
	typedef unsigned long ISTDUINT32; 
	typedef long ISTDINT32;
#endif
#endif


//=====================================================================
// Integer Definition
//=====================================================================
// comment: 8 位 int 类型定义
#ifndef __IINT8_DEFINED
#define __IINT8_DEFINED
typedef char IINT8;
#endif

// comment: 8 位 uint 类型定义
#ifndef __IUINT8_DEFINED
#define __IUINT8_DEFINED
typedef unsigned char IUINT8;
#endif

// comment: 16 位 uint 类型定义
#ifndef __IUINT16_DEFINED
#define __IUINT16_DEFINED
typedef unsigned short IUINT16;
#endif

// comment: 16 位 int 类型定义
#ifndef __IINT16_DEFINED
#define __IINT16_DEFINED
typedef short IINT16;
#endif

// comment: 32 位 int 类型定义
#ifndef __IINT32_DEFINED
#define __IINT32_DEFINED
typedef ISTDINT32 IINT32;
#endif

// comment: 32 位 uint 类型定义
#ifndef __IUINT32_DEFINED
#define __IUINT32_DEFINED
typedef ISTDUINT32 IUINT32;
#endif

// comment: 64 位 int 类型定义
#ifndef __IINT64_DEFINED
#define __IINT64_DEFINED
#if defined(_MSC_VER) || defined(__BORLANDC__)
typedef __int64 IINT64;
#else
typedef long long IINT64;
#endif
#endif

// comment: 64 位 uint 类型定义
#ifndef __IUINT64_DEFINED
#define __IUINT64_DEFINED
#if defined(_MSC_VER) || defined(__BORLANDC__)
typedef unsigned __int64 IUINT64;
#else
typedef unsigned long long IUINT64;
#endif
#endif

// comment: inline 定义
#ifndef INLINE
#if defined(__GNUC__)

#if (__GNUC__ > 3) || ((__GNUC__ == 3) && (__GNUC_MINOR__ >= 1))
#define INLINE         __inline__ __attribute__((always_inline))
#else
#define INLINE         __inline__
#endif

#elif (defined(_MSC_VER) || defined(__BORLANDC__) || defined(__WATCOMC__))
#define INLINE __inline
#else
#define INLINE 
#endif
#endif

#if (!defined(__cplusplus)) && (!defined(inline))
#define inline INLINE
#endif


// comment: 自定义循环队列 及 相关操作
//=====================================================================
// QUEUE DEFINITION                                                  
//=====================================================================
#ifndef __IQUEUE_DEF__
#define __IQUEUE_DEF__

struct IQUEUEHEAD {
	struct IQUEUEHEAD *next, *prev;
};

// comment: iqueue_head 队列头定义，包含了前驱后驱两个指针
typedef struct IQUEUEHEAD iqueue_head;


//---------------------------------------------------------------------
// queue init                                                         
//---------------------------------------------------------------------
// comment: 初始化一个新的队列head结构，前后指针均指向自己
#define IQUEUE_HEAD_INIT(name) { &(name), &(name) }
#define IQUEUE_HEAD(name) \
	struct IQUEUEHEAD name = IQUEUE_HEAD_INIT(name)

// comment: 重置队列head结构，将前后指针指向自己
#define IQUEUE_INIT(ptr) ( \
	(ptr)->next = (ptr), (ptr)->prev = (ptr))

// comment: 得到结构体成员的地址偏移（一个小trick）
#define IOFFSETOF(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

// comment: 根据结构体成员地址得到结构体首地址（该结构体指针）
#define ICONTAINEROF(ptr, type, member) ( \
		(type*)( ((char*)((type*)ptr)) - IOFFSETOF(type, member)) )

// comment: 根据队列结构体成员地址得到队列头地址 ??
#define IQUEUE_ENTRY(ptr, type, member) ICONTAINEROF(ptr, type, member)


// comment: 队列操作
//---------------------------------------------------------------------
// queue operation                     
//---------------------------------------------------------------------
// comment: 将 node 插入到 head 后面，head_prev - head - (node) - origin_head_next
#define IQUEUE_ADD(node, head) ( \
	(node)->prev = (head), (node)->next = (head)->next, \
	(head)->next->prev = (node), (head)->next = (node))

// comment: 将 node 插入到 head 前面，origin_head_prev - (node) - head - head_next
#define IQUEUE_ADD_TAIL(node, head) ( \
	(node)->prev = (head)->prev, (node)->next = (head), \
	(head)->prev->next = (node), (head)->prev = (node))

// comment: 删除队列节点 p 和节点 n 之间的节点
#define IQUEUE_DEL_BETWEEN(p, n) ((n)->prev = (p), (p)->next = (n))

// comment: 从队列中删除节点 entry
#define IQUEUE_DEL(entry) (\
	(entry)->next->prev = (entry)->prev, \
	(entry)->prev->next = (entry)->next, \
	(entry)->next = 0, (entry)->prev = 0)

// comment: 从队列中删除节点 entry，并重置
#define IQUEUE_DEL_INIT(entry) do { \
	IQUEUE_DEL(entry); IQUEUE_INIT(entry); } while (0)

// comment: 判断队列是否为空
#define IQUEUE_IS_EMPTY(entry) ((entry) == (entry)->next)

// comment: 定义小写宏
#define iqueue_init		IQUEUE_INIT
#define iqueue_entry	IQUEUE_ENTRY
#define iqueue_add		IQUEUE_ADD
#define iqueue_add_tail	IQUEUE_ADD_TAIL
#define iqueue_del		IQUEUE_DEL
#define iqueue_del_init	IQUEUE_DEL_INIT
#define iqueue_is_empty IQUEUE_IS_EMPTY

// comment: 遍历循环队列所在的结构，这里的队列结构是其他结构类型的一个成员
#define IQUEUE_FOREACH(iterator, head, TYPE, MEMBER) \
	for ((iterator) = iqueue_entry((head)->next, TYPE, MEMBER); \
		&((iterator)->MEMBER) != (head); \
		(iterator) = iqueue_entry((iterator)->MEMBER.next, TYPE, MEMBER))

// comment: 定义小写宏
#define iqueue_foreach(iterator, head, TYPE, MEMBER) \
	IQUEUE_FOREACH(iterator, head, TYPE, MEMBER)

// comment: 遍历循环队列 entry，注意与 iqueue_foreach 的区别
#define iqueue_foreach_entry(pos, head) \
	for( (pos) = (head)->next; (pos) != (head) ; (pos) = (pos)->next )
	
// comment: 在head 指向的队列位置处插入一段其他队列
// comment: 这里小 trick 是用一个队列结构头来表示这段插入的队列，
// comment: next指向新队列的头，prev指向新队列的尾
// comment: head - list.next - ... - list.prev - at
#define __iqueue_splice(list, head) do {	\
		iqueue_head *first = (list)->next, *last = (list)->prev; \
		iqueue_head *at = (head)->next; \
		(first)->prev = (head), (head)->next = (first);		\
		(last)->next = (at), (at)->prev = (last); }	while (0)

// comment: 定义小写宏，对于空 list 不执行操作
#define iqueue_splice(list, head) do { \
	if (!iqueue_is_empty(list)) __iqueue_splice(list, head); } while (0)

// comment: 执行完 splice 操作后，将 list 重置
#define iqueue_splice_init(list, head) do {	\
	iqueue_splice(list, head);	iqueue_init(list); } while (0)


// comment: windows 平台下，禁止一些编译 warning
#ifdef _MSC_VER
#pragma warning(disable:4311)
#pragma warning(disable:4312)
#pragma warning(disable:4996)
#endif

#endif


// comment: 字节序 和 字节对齐 相关
//---------------------------------------------------------------------
// BYTE ORDER & ALIGNMENT
//---------------------------------------------------------------------
#ifndef IWORDS_BIG_ENDIAN
    #ifdef _BIG_ENDIAN_
        #if _BIG_ENDIAN_
            #define IWORDS_BIG_ENDIAN 1
        #endif
    #endif
    #ifndef IWORDS_BIG_ENDIAN
        #if defined(__hppa__) || \
            defined(__m68k__) || defined(mc68000) || defined(_M_M68K) || \
            (defined(__MIPS__) && defined(__MIPSEB__)) || \
            defined(__ppc__) || defined(__POWERPC__) || defined(_M_PPC) || \
            defined(__sparc__) || defined(__powerpc__) || \
            defined(__mc68000__) || defined(__s390x__) || defined(__s390__)
            #define IWORDS_BIG_ENDIAN 1
        #endif
    #endif
    #ifndef IWORDS_BIG_ENDIAN
        #define IWORDS_BIG_ENDIAN  0
    #endif
#endif

#ifndef IWORDS_MUST_ALIGN
	#if defined(__i386__) || defined(__i386) || defined(_i386_)
		#define IWORDS_MUST_ALIGN 0
	#elif defined(_M_IX86) || defined(_X86_) || defined(__x86_64__)
		#define IWORDS_MUST_ALIGN 0
	#elif defined(__amd64) || defined(__amd64__)
		#define IWORDS_MUST_ALIGN 0
	#else
		#define IWORDS_MUST_ALIGN 1
	#endif
#endif


//=====================================================================
// SEGMENT
//=====================================================================
// comment: segment 结构体
struct IKCPSEG
{
    // comment: 循环队列
	struct IQUEUEHEAD node;
    // comment: 会话号
	IUINT32 conv;
    // comment: 包控制指令，包类型
	IUINT32 cmd;
    // comment: fragment 分段号，stream 模式 frg 为 0，否则为对应整包分段后的序号
	IUINT32 frg;
    // comment: 当前接收窗口大小
	IUINT32 wnd;
    // comment: 时间戳
	IUINT32 ts;
    // comment: segment 序号
    IUINT32 sn;
    // comment: unacknowledge ack，当前没有确认的 segment 序号
	IUINT32 una;
    // comment: segment 消息长度
	IUINT32 len;
    // comment: 重传时间戳
	IUINT32 resendts;
    // comment: 重传时间间隔
	IUINT32 rto;
    // comment: 快速重传 ack 计数（收到大于自己序号的 ack 确认的次数）
	IUINT32 fastack;
    // comment: 快速重传次数
	IUINT32 xmit;
    // 消息
	char data[1];
};


//---------------------------------------------------------------------
// IKCPCB
//---------------------------------------------------------------------
// comment: KCP Control oBject 结构体
struct IKCPCB
{
    // comment: conv - 会话号
    // comment: mtu - max transmission unit，最大发送单元大小
    // comment: mss - max segment size，单个报文段最大大小
    // comment: state - 会话状态标志，标记会话是否连接正常
	IUINT32 conv, mtu, mss, state;
    // comment: snd_una - 已经发送但还没有得到 ack 确认的第一个 segment 序号
    // comment: snd_nxt - 下一个要发送的 segment 序号
    // comment: rcv_nxt - 下一个需要接收的 segment 序号
	IUINT32 snd_una, snd_nxt, rcv_nxt;
	IUINT32 ts_recent, ts_lastack, ssthresh;
	IINT32 rx_rttval, rx_srtt, rx_rto, rx_minrto;
    // comment: snd_wnd - 发送窗口大小
    // comment: rcv_wnd - 接收窗口大小
    // comment: rmt_wnd - 对方接收窗口大小
    // comment: cwnd - 发送窗口限制
    // comment: probe - 接收窗口查询标记
    IUINT32 snd_wnd, rcv_wnd, rmt_wnd, cwnd, probe;
    // comment: current - 当前时间戳
    // comment: interval - update 间隔
    // comment: ts_flush - flush 发送数据时间戳
    // comment: xmit - 全局重传计数
	IUINT32 current, interval, ts_flush, xmit;
    // comment: nrcv_buf - 当前 rcv_buf 中的 segment 数量
    // comment: nsnd_buf - 当前 snd_buf 中的 segment 数量
    IUINT32 nrcv_buf, nsnd_buf;
    // comment: nrcv_que - 当前 rcv_queue 中的 segment 数量
    // comment: nsnd_que - 当前 snd_queue 中的 segment 数量
	IUINT32 nrcv_que, nsnd_que;
    // comment: nodelay - 是否有重传延时
    // comment: updated - 是否调用过 update 函数
	IUINT32 nodelay, updated;
    // comment: ts_probe - 下次 probe 查询时间点
    // comment: probe_wait - probe 定时标志，到下次 probe 的等待时长
	IUINT32 ts_probe, probe_wait;
    // comment: dead_link - 导致会话失效的重传次数
    // comment: incr -
	IUINT32 dead_link, incr;
    // comment: snd_queue - 发送队列
	struct IQUEUEHEAD snd_queue;
    // comment: rcv_queue - 接收队列（已经经过 ack 确认的数据）
	struct IQUEUEHEAD rcv_queue;
    // comment: snd_buf - 发送 buffer
	struct IQUEUEHEAD snd_buf;
    // comment: rcv_buf - 接收 buffer
	struct IQUEUEHEAD rcv_buf;
    // comment: acklist - 对方数据包的 ack 序号列表
    // comment: ackcount - 对方数据包的 ack 序号列表数量
    // comment: ackblock - ack 序号列表容量
	IUINT32 *acklist;
	IUINT32 ackcount;
	IUINT32 ackblock;
    // comment: user - 用户自定义指针，会在 output 和 writelog 接口中传入
	void *user;
    // comment: 数据编码临时 buffer 空间
	char *buffer;
    // comment: fastresend - 快速重传标志，同时也用于控制快速重传的开始
    // comment: fastlimit - 快速重传的次数限制
	int fastresend;
	int fastlimit;
    // comment: nocwnd - 在快速重传和丢包时，是否需要限制发送窗口大小
    // comment: stream - 是否是流失传输
	int nocwnd, stream;
    // comment: logmask - 日志 mask
	int logmask;
    // comment: output - 底层通信 send 方法，kcp 是纯算法逻辑，需要设定底层通信方法
	int (*output)(const char *buf, int len, struct IKCPCB *kcp, void *user);
    // comment: writelog - 自定义写日志接口
    void (*writelog)(const char *log, struct IKCPCB *kcp, void *user);
};


// comment: 小写
typedef struct IKCPCB ikcpcb;

// comment: 日志类型宏
#define IKCP_LOG_OUTPUT			1
#define IKCP_LOG_INPUT			2
#define IKCP_LOG_SEND			4
#define IKCP_LOG_RECV			8
#define IKCP_LOG_IN_DATA		16
#define IKCP_LOG_IN_ACK			32
#define IKCP_LOG_IN_PROBE		64
#define IKCP_LOG_IN_WINS		128
#define IKCP_LOG_OUT_DATA		256
#define IKCP_LOG_OUT_ACK		512
#define IKCP_LOG_OUT_PROBE		1024
#define IKCP_LOG_OUT_WINS		2048

#ifdef __cplusplus
extern "C" {
#endif

//---------------------------------------------------------------------
// interface
//---------------------------------------------------------------------

// comment: 创建 kcp 控制结构体
// create a new kcp control object, 'conv' must equal in two endpoint
// from the same connection. 'user' will be passed to the output callback
// output callback can be setup like this: 'kcp->output = my_udp_output'
ikcpcb* ikcp_create(IUINT32 conv, void *user);

// comment: 释放 kcp 控制结构体
// release kcp control object
void ikcp_release(ikcpcb *kcp);

// comment: 设置 kcp 的 output 函数指针
// set output callback, which will be invoked by kcp
void ikcp_setoutput(ikcpcb *kcp, int (*output)(const char *buf, int len, 
	ikcpcb *kcp, void *user));

// comment: 上层的 recv 函数（是已经 ack 过的 segment）
// comment: kcp - kcp 控制对象
// comment: buffer - 用于存储 kcp 中消息的 buffer
// comment: len - 想要从 kcp 中获取的字节数（小于 0 的 len 值代表 peek 操作）
// comment: return -1 - 接收队列为空
// comment: return -2 - 没有可以获取的消息
// comment: return -3 - len 小于 rcv_queue 中的消息长度，不允许获取部分
// comment: return > 0 - 获取到的消息长度
// user/upper level recv: returns size, returns below zero for EAGAIN
int ikcp_recv(ikcpcb *kcp, char *buffer, int len);

// comment: 上层的 send 函数
// comment: kcp - kcp 控制对象
// comment: buffer - 想要发送的消息 buffer
// comment: len - 想要发送的消息长度，len可以等于 0，可以发送空包
// comment: return -1 - len 大小错误，小于 0
// comment: return -2 - segment 创建失败
// comment: return  0 - 发送成功，数据成功加入 snd_queue
// user/upper level send, returns below zero for error
int ikcp_send(ikcpcb *kcp, const char *buffer, int len);

// update state (call it repeatedly, every 10ms-100ms), or you can ask 
// ikcp_check when to call it again (without ikcp_input/_send calling).
// 'current' - current timestamp in millisec. 
void ikcp_update(ikcpcb *kcp, IUINT32 current);

// Determine when should you invoke ikcp_update:
// returns when you should invoke ikcp_update in millisec, if there 
// is no ikcp_input/_send calling. you can call ikcp_update in that
// time, instead of call update repeatly.
// Important to reduce unnacessary ikcp_update invoking. use it to 
// schedule ikcp_update (eg. implementing an epoll-like mechanism, 
// or optimize ikcp_update when handling massive kcp connections)
IUINT32 ikcp_check(const ikcpcb *kcp, IUINT32 current);

// when you received a low level packet (eg. UDP packet), call it
// comment: 接收到元数据
int ikcp_input(ikcpcb *kcp, const char *data, long size);

// flush pending data
// comment: 发送数据，处理 ack 确认、查询发送窗口、快速重传、超时重传等
void ikcp_flush(ikcpcb *kcp);

// check the size of next message in the recv queue
// comment: recv queue 中下一个 message 的大小，以 frg == 0 为界限
// comment: 如果是 stream 类型，frg 都为 0，如果不是， frg == 0 的 segment 是最后一段 fragment
int ikcp_peeksize(const ikcpcb *kcp);

// change MTU size, default is 1400
// comment: 设置 mtu 大小
// comment: return -1 - 新的 mtu 大小过小
// comment: return -2 - 新的 buffer 创建失败
// comment: return  0 - 设置成功
int ikcp_setmtu(ikcpcb *kcp, int mtu);

// set maximum window size: sndwnd=32, rcvwnd=32 by default
// comment: 设置发送窗口和接收窗口大小
int ikcp_wndsize(ikcpcb *kcp, int sndwnd, int rcvwnd);

// get how many packet is waiting to be sent
// comment: 还有多少包等待发送，snd_buf 大小 + snd_queue 大小
int ikcp_waitsnd(const ikcpcb *kcp);

// fastest: ikcp_nodelay(kcp, 1, 20, 2, 1)
// nodelay: 0:disable(default), 1:enable
// interval: internal update timer interval in millisec, default is 100ms 
// resend: 0:disable fast resend(default), 1:enable fast resend
// nc: 0:normal congestion control(default), 1:disable congestion control
// comment: 设置 kcp 性能控制参数
// comment: nodelay - 重传延时，0 - 关闭（默认），1 - 打开
// comment: interval - update 间隔
// comment: resend - 快速重传，0 - 关闭（默认），1 - 打开
// comment: nc - 拥塞控制，0 - 打开（默认），1 - 关闭
int ikcp_nodelay(ikcpcb *kcp, int nodelay, int interval, int resend, int nc);


// comment: log 接口
void ikcp_log(ikcpcb *kcp, int mask, const char *fmt, ...);

// setup allocator
// comment: 自定义内存分配接口
void ikcp_allocator(void* (*new_malloc)(size_t), void (*new_free)(void*));

// read conv
// comment: 从数据包中解析出 会话编号 conv
IUINT32 ikcp_getconv(const void *ptr);


#ifdef __cplusplus
}
#endif

#endif


