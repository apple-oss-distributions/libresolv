
#ifndef _PORT_BEFORE_H_
#define _PORT_BEFORE_H_

#ifndef __APPLE__
#define _LIBC		1
#endif /* !__APPLE__ */
#define DO_PTHREADS	1
#ifndef __APPLE__
#define USE_POLL	1
#endif /* !__APPLE__ */
#define HAVE_MD5	1

#define ISC_SOCKLEN_T	socklen_t
#define ISC_FORMAT_PRINTF(fmt, args) \
	__attribute__((__format__(__printf__, fmt, args)))
#define DE_CONST(konst, var) \
        do { \
                union { const void *k; void *v; } _u; \
                _u.k = konst; \
                var = _u.v; \
        } while (0)

#define UNUSED(x) (void)(x)

#endif /* _PORT_BEFORE_H_ */
