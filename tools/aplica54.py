import sys, os, re
# uso: aplica<54|73>.py <arvore-fonte> [1|2|all]
#   1   = rodada 1 (CVE-2026-109618/109619, incl. PR #1 e issue #2)
#   2   = rodada 2 (CVE-2026-126714/129496), sobre uma arvore ja com a rodada 1
#   all = as duas (padrao)
root = sys.argv[1]
RODADA = sys.argv[2] if len(sys.argv) > 2 else 'all'
if RODADA not in ('1', '2', 'all'):
    sys.exit("rodada invalida: %s" % RODADA)
ATIVO = True
def rodada(n):
    global ATIVO
    ATIVO = RODADA in (n, 'all')
def sub(path, old, new, count=1):
    if not ATIVO:
        return
    p = os.path.join(root, path)
    s = open(p, encoding='latin-1').read()
    n = s.count(old)
    if count == -1:
        if n < 1:
            sys.exit("%s: esperado >=1 ocorrencia(s), achou 0:\n%s" % (path, old[:200]))
    elif n != count:
        sys.exit("%s: esperado %d ocorrencia(s), achou %d:\n%s" % (path, count, n, old[:200]))
    open(p, 'w', encoding='latin-1').write(s.replace(old, new))

def insere_apos_regex(path, pat, texto):
    if not ATIVO:
        return
    p = os.path.join(root, path)
    s = open(p, encoding='latin-1').read()
    m = list(re.finditer(pat, s))
    if len(m) != 1:
        sys.exit("%s: regex casou %d vezes: %s" % (path, len(m), pat))
    i = m[0].end()
    open(p, 'w', encoding='latin-1').write(s[:i] + texto + s[i:])

rodada('1')
# 1) OOM / overflow: nao usar longjmp (bailout); encerrar o worker (CVE-2026-109618)
sub('Zend/zend_alloc.c', """#if ZEND_DEBUG && defined(HAVE_KILL) && defined(HAVE_GETPID)
	kill(getpid(), SIGSEGV);
#endif
	exit(1);
}
""", """#if ZEND_DEBUG && defined(HAVE_KILL) && defined(HAVE_GETPID)
	kill(getpid(), SIGSEGV);
#endif
	_exit(1);
}

/* Backport CVE-2026-109618: fatal de memoria sem longjmp(); encerra o processo */
ZEND_API void zend_mm_safe_error_ex(const char *format, ...)
{
	const char *error_filename = NULL;
	uint error_lineno = 0;
	char buf[1024];
	va_list args;
	TSRMLS_FETCH();

	if (zend_is_compiling(TSRMLS_C)) {
		error_filename = zend_get_compiled_filename(TSRMLS_C);
		error_lineno = zend_get_compiled_lineno(TSRMLS_C);
	} else if (EG(in_execution)) {
		error_filename = EG(active_op_array)?EG(active_op_array)->filename:NULL;
		error_lineno = EG(opline_ptr)?(*EG(opline_ptr))->lineno:0;
	}

	va_start(args, format);
	vsnprintf(buf, sizeof(buf), format, args);
	va_end(args);

	fprintf(stderr, "\\nFatal error: %s in %s on line %d\\n", buf,
		error_filename ? error_filename : "Unknown", error_lineno);
/* See http://support.microsoft.com/kb/190351 */
#ifdef PHP_WIN32
	fflush(stderr);
#endif
	_exit(1);
}
""")

# zend_mm_safe_error inteiro -> chama a versao sem bailout
if ATIVO:
    p = os.path.join(root, 'Zend/zend_alloc.c')
    s = open(p, encoding='latin-1').read()
    ini = s.index('static void zend_mm_safe_error(zend_mm_heap *heap,')
    corpo = s.index('{', ini)
    fim = s.index('\tzend_bailout();\n}\n', corpo) + len('\tzend_bailout();\n}\n')
    s = s[:corpo] + """{
	(void) heap;
	zend_mm_safe_error_ex(format,
		limit,
#if ZEND_DEBUG
		filename,
		lineno,
#endif
		size);
}
""" + s[fim:]
    open(p, 'w', encoding='latin-1').write(s)

sub('Zend/zend_alloc.c', 'zend_error_noreturn(E_ERROR, "Possible integer overflow in memory allocation (%zu * %zu + %zu)", nmemb, size, offset);',
    'zend_mm_safe_error_ex("Possible integer overflow in memory allocation (%zu * %zu + %zu)", nmemb, size, offset);', -1)
sub('Zend/zend_alloc.h', 'END_EXTERN_C()\n', '''ZEND_API void zend_mm_safe_error_ex(const char *format, ...);

END_EXTERN_C()
''')

# 2) session upload progress desligado no codigo (CVE-2026-109619)
sub('ext/session/session.c', '''	if (!PS(rfc1867_enabled)) {
		return retval;
	}

	progress = PS(rfc1867_progress);''', '''	if (!PS(rfc1867_enabled) || 1) { /* Backport CVE-2026-109619: upload progress desativado */
		return retval;
	}

	progress = PS(rfc1867_progress);''')

# 3) SAPI: zerar ponteiros liberados
for campo in ('auth_user', 'auth_password', 'auth_digest', 'content_type_dup', 'current_user'):
    sub('main/SAPI.c', '''	if (SG(request_info).%s) {
		efree(SG(request_info).%s);
	}
''' % (campo, campo), '''	if (SG(request_info).%s) {
		efree(SG(request_info).%s);
		SG(request_info).%s = NULL;
	}
''' % (campo, campo, campo))

# 4) main.c: superglobais e modules_activated nao sobrevivem ao request
sub('main/main.c', '''			if (PG(http_globals)[i]) {
				zval_ptr_dtor(&PG(http_globals)[i]);
			}
''', '''			if (PG(http_globals)[i]) {
				zval_ptr_dtor(&PG(http_globals)[i]);
				/* May be accessed before php_request_startup() */
				PG(http_globals)[i] = NULL;
			}
''', 2)
sub('main/main.c', '''	/* 12. Reset max_execution_time */
	zend_try {
		zend_unset_timeout(TSRMLS_C);
	} zend_end_try();
''', '''	/* 12. Reset max_execution_time */
	zend_try {
		zend_unset_timeout(TSRMLS_C);
	} zend_end_try();

	/* May be accessed before php_request_startup() */
	PG(modules_activated) = 0;
''')
insere_apos_regex('main/main.c', r'\n\tPHP_INI_ENTRY\("max_file_uploads",[^\n]*\n', '\tPHP_INI_ENTRY("max_multipart_body_parts",\t"-1",\t\tPHP_INI_SYSTEM|PHP_INI_PERDIR,\t\tNULL)\n')

# 5) executor: estado de erro/excecao zerado no fim do request
sub('Zend/zend_execute_API.c', '''		zend_objects_store_destroy(&EG(objects_store));
		if (EG(in_autoload)) {
			zend_hash_destroy(EG(in_autoload));
			FREE_HASHTABLE(EG(in_autoload));
		}
	} zend_end_try();

	zend_shutdown_fpu(TSRMLS_C);
''', '''		zend_objects_store_destroy(&EG(objects_store));
		if (EG(in_autoload)) {
			zend_hash_destroy(EG(in_autoload));
			FREE_HASHTABLE(EG(in_autoload));
		}
	} zend_end_try();

	/* Backport CVE-2026-109619: may be used by zend_error before init_executor */
	EG(user_error_handler) = NULL;
	EG(user_exception_handler) = NULL;
	memset(&EG(user_error_handlers_error_reporting), 0, sizeof(EG(user_error_handlers_error_reporting)));
	memset(&EG(user_error_handlers), 0, sizeof(EG(user_error_handlers)));
	memset(&EG(user_exception_handlers), 0, sizeof(EG(user_exception_handlers)));
	EG(error_handling) = EH_NORMAL;
	EG(exception) = NULL;
	EG(in_autoload) = NULL;

	zend_shutdown_fpu(TSRMLS_C);
''')

# 6) llist
sub('Zend/zend_llist.c', '''		current = next;
	}

	l->count = 0;
}''', '''		current = next;
	}

	l->head  = NULL;
	l->tail  = NULL;
	l->count = 0;
}''')

# 7) rfc1867: guardar so os headers usados, sem duplicados; limite de partes
sub('main/rfc1867.c', '''/* parse headers */
static int multipart_buffer_headers(''', '''static zend_bool php_mime_should_save_hdr(const char *name)
{
	return !strcasecmp(name, "Content-Disposition")
		|| !strcasecmp(name, "Content-Type");
}

static char *php_mime_get_hdr_value(zend_llist header, char *key);

/* parse headers */
static int multipart_buffer_headers(''')
sub('main/rfc1867.c', '''			*value = '\\0';
			do { value++; } while(isspace(*value));

			key = estrdup(line);
			smart_str_appends(&buf_value, value);
''', '''			*value = '\\0';

			/* Keep only headers we use, and ignore duplicates */
			if (!php_mime_should_save_hdr(line)
					|| php_mime_get_hdr_value(*header, line)) {
				key = NULL;
			} else {
				key = estrdup(line);
				do { value++; } while(isspace((unsigned char)*value));
				smart_str_appends(&buf_value, value);
			}
''')
sub('main/rfc1867.c', '''	int upload_cnt = INI_INT("max_file_uploads");
''', '''	int upload_cnt = INI_INT("max_file_uploads");
	int body_parts_cnt = INI_INT("max_multipart_body_parts");
	int body_parts_limit;
''')
sub('main/rfc1867.c', '''	zend_llist_init(&header, sizeof(mime_header_entry), (llist_dtor_func_t) php_free_hdr_entry, 0);
''', '''	if (body_parts_cnt < 0) {
		body_parts_cnt = PG(max_input_vars) + upload_cnt;
	}
	body_parts_limit = body_parts_cnt;

	zend_llist_init(&header, sizeof(mime_header_entry), (llist_dtor_func_t) php_free_hdr_entry, 0);
''')
sub('main/rfc1867.c', '''		if ((cd = php_mime_get_hdr_value(header, "Content-Disposition"))) {
			char *pair = NULL;
			int end = 0;
''', '''		if ((cd = php_mime_get_hdr_value(header, "Content-Disposition"))) {
			char *pair = NULL;
			int end = 0;

			if (--body_parts_cnt < 0) {
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "Multipart body parts limit exceeded %d. To increase the limit change max_multipart_body_parts in php.ini.", body_parts_limit);
				goto fileupload_done;
			}
''')

# 1b) PR #1: falhas de alocacao restantes do commit oficial 712e60f9ed
#     (malloc/realloc persistente e Balloc) tambem sem longjmp/exit handlers
sub('Zend/zend_alloc.c', '''	_exit(1);
}

/*******************/
/* Storage Manager */''', '''	_exit(1);
}

/* Backport CVE-2026-109618: persistent allocation failure must not run
 * exit handlers on a possibly inconsistent state */
ZEND_API void zend_out_of_memory(void)
{
	fprintf(stderr, "Out of memory\\n");
/* See http://support.microsoft.com/kb/190351 */
#ifdef PHP_WIN32
	fflush(stderr);
#endif
	_exit(1);
}

/*******************/
/* Storage Manager */''')
sub('Zend/zend_alloc.h', '''inline static void * __zend_malloc(size_t len)
{''', '''#if defined(__GNUC__) && __GNUC__ >= 3 && !defined(__INTEL_COMPILER) && !defined(DARWIN) && !defined(__hpux) && !defined(_AIX) && !defined(__osf__)
ZEND_API void zend_out_of_memory(void) __attribute__ ((noreturn));
#else
ZEND_API void zend_out_of_memory(void);
#endif

inline static void * __zend_malloc(size_t len)
{''')
sub('Zend/zend_alloc.h', '''	fprintf(stderr, "Out of memory\\n");
	exit(1);
}''', '''	zend_out_of_memory();
	return NULL;
}''', 2)
sub('Zend/zend_strtod.c', 'zend_error(E_ERROR, "Balloc() failed to allocate memory");',
    'zend_mm_safe_error_ex("Balloc() failed to allocate memory");')

# 1c) issue #2: fatais restantes da familia 5.x, mesmo tratamento
sub('Zend/zend_strtod.c', 'zend_error(E_ERROR, "Balloc() allocation exceeds list boundary");',
    'zend_mm_safe_error_ex("Balloc() allocation exceeds list boundary");')
sub('Zend/zend_operators.c', 'zend_error(E_ERROR, "String size overflow");',
    'zend_mm_safe_error_ex("String size overflow");', -1)
if os.path.exists(os.path.join(root, 'Zend/zend_alloc.c')) and \
   'String allocation overflow' in open(os.path.join(root, 'Zend/zend_alloc.c'), encoding='latin-1').read():
    sub('Zend/zend_alloc.c', 'zend_error_noreturn(E_ERROR, "String allocation overflow, max size is %d", INT_MAX);',
        'zend_mm_safe_error_ex("String allocation overflow, max size is %d", INT_MAX);')

rodada('2')
# 8) CVE-2026-126714 (GHSA-fm2m-fjf5-v3cp): sessao 'files' sempre truncada antes de gravar
#    (upstream e2d3cee9ad). Escrita interrompida nao deixa mais sufixo da sessao antiga.
sub('ext/session/mod_files.c', '''	/* Truncate file if the amount of new data is smaller than the existing data set. */

	if (vallen < (int)data->st_size) {
		php_ignore_value(ftruncate(data->fd, 0));
	}
''', '''	/* Backport CVE-2026-126714: truncar SEMPRE antes de gravar; falhou, aborta */
	if (ftruncate(data->fd, 0) != 0) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "ftruncate() failed: %s (%d)", strerror(errno), errno);
		return FAILURE;
	}
''')

# 9) CVE-2026-129496 (GHSA-gr4f-wgx5-jpfv): timestamp do error_log em UTC fora de request ativo
#    (upstream cb20015e04). Evita usar o cache de timezone liberado no startup.
sub('main/main.c', '''#ifdef ZTS
			if (!php_during_module_startup()) {
				error_time_str = php_format_date("d-M-Y H:i:s e", 13, error_time, 1 TSRMLS_CC);
			} else {
				error_time_str = php_format_date("d-M-Y H:i:s e", 13, error_time, 0 TSRMLS_CC);
			}
#else
			error_time_str = php_format_date("d-M-Y H:i:s e", 13, error_time, 1 TSRMLS_CC);
#endif
''', '''			/* Backport CVE-2026-129496: hora local so com request ativo; senao UTC */
			error_time_str = php_format_date("d-M-Y H:i:s e", 13, error_time, PG(modules_activated) && EG(active) TSRMLS_CC);
''')

print("ok")
