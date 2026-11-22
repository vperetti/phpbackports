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
            sys.exit("%s: esperado >=1, achou 0:\n%s" % (path, old[:160]))
    elif n != count:
        sys.exit("%s: esperado %d, achou %d:\n%s" % (path, count, n, old[:160]))
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

def insere_apos_ultima(path, anchor, texto, esperado):
    if not ATIVO:
        return
    p = os.path.join(root, path)
    s = open(p, encoding='latin-1').read()
    n = s.count(anchor)
    if n != esperado:
        sys.exit("%s: ancora '%s' aparece %d vezes (esperado %d)" % (path, anchor[:60], n, esperado))
    i = s.rfind(anchor) + len(anchor)
    open(p, 'w', encoding='latin-1').write(s[:i] + texto + s[i:])

rodada('1')
# --- CVE-2026-109618: OOM sem longjmp/bailout ---
sub('Zend/zend_alloc.c', '''#if ZEND_DEBUG && defined(HAVE_KILL) && defined(HAVE_GETPID)
	kill(getpid(), SIGSEGV);
#endif
	exit(1);
}

static ZEND_COLD ZEND_NORETURN void zend_mm_safe_error(zend_mm_heap *heap,''',
'''#if ZEND_DEBUG && defined(HAVE_KILL) && defined(HAVE_GETPID)
	kill(getpid(), SIGSEGV);
#endif
	_exit(1);
}

/* Backport CVE-2026-109618: fatal de memoria sem bailout; encerra o processo */
ZEND_API ZEND_COLD ZEND_NORETURN void zend_mm_safe_error_ex(const char *format, ...)
{
	zend_string *script_filename = NULL;
	uint32_t script_lineno = 0;
	char buf[1024];
	va_list args;

	if (zend_is_executing()) {
		script_filename = zend_get_executed_filename_ex();
		script_lineno = zend_get_executed_lineno();
	} else if (zend_is_compiling()) {
		script_filename = zend_get_compiled_filename();
		script_lineno = zend_get_compiled_lineno();
	}

	va_start(args, format);
	vsnprintf(buf, sizeof(buf), format, args);
	va_end(args);

	fprintf(stderr, "\\nFatal error: %s in %s on line %d\\n", buf,
		script_filename ? ZSTR_VAL(script_filename) : "Unknown", script_lineno);
#ifdef ZEND_WIN32
	fflush(stderr);
#endif
	_exit(1);
}

static ZEND_COLD ZEND_NORETURN void zend_mm_safe_error(zend_mm_heap *heap,''')

sub('Zend/zend_alloc.c', '''	size_t size)
{

	heap->overflow = 1;
	zend_try {
		zend_error_noreturn(E_ERROR,
			format,
			limit,
#if ZEND_DEBUG
			filename,
			lineno,
#endif
			size);
	} zend_catch {
	}  zend_end_try();
	heap->overflow = 0;
	zend_bailout();
	exit(1);
}''',
'''	size_t size)
{
	(void) heap;
	zend_mm_safe_error_ex(format,
		limit,
#if ZEND_DEBUG
		filename,
		lineno,
#endif
		size);
}''')

sub('Zend/zend_alloc.c', '''	fprintf(stderr, "Out of memory\\n");
	exit(1);
}''', '''	fprintf(stderr, "Out of memory\\n");
	_exit(1);
}''')

# include necessario e inclui zend_execute.h para as funcoes de linha/arquivo
sub('Zend/zend_alloc.c', '#include "zend_multiply.h"\n',
    '#include "zend_multiply.h"\n#include "zend_execute.h"\n')

sub('Zend/zend_alloc.h', 'END_EXTERN_C()\n',
    'ZEND_API ZEND_COLD ZEND_NORETURN void zend_mm_safe_error_ex(const char *format, ...);\n\nEND_EXTERN_C()\n')

# --- CVE-2026-109619: estado global nao sobrevive ao request ---
# session upload progress desligado no codigo
sub('ext/session/session.c', '''	if (!PS(rfc1867_enabled)) {
		return retval;
	}''', '''	if (!PS(rfc1867_enabled) || 1) { /* Backport CVE-2026-109619 */
		return retval;
	}''')

# SAPI: zerar ponteiros liberados
for campo in ('auth_user', 'auth_password', 'auth_digest', 'content_type_dup', 'current_user'):
    sub('main/SAPI.c', '''	if (SG(request_info).%s) {
		efree(SG(request_info).%s);
	}
''' % (campo, campo), '''	if (SG(request_info).%s) {
		efree(SG(request_info).%s);
		SG(request_info).%s = NULL;
	}
''' % (campo, campo, campo))

# shutdown_executor: resetar estado global antes de init_executor (uniforme p/ 7.0-7.3)
# Inserido apos a ultima "EG(ht_iterators_used) = 0;", no fim de shutdown_executor.
insere_apos_ultima('Zend/zend_execute_API.c', '\tEG(ht_iterators_used) = 0;\n', '''
	/* Backport CVE-2026-109619: estado que pode ser acessado antes de init_executor */
	ZVAL_UNDEF(&EG(user_error_handler));
	ZVAL_UNDEF(&EG(user_exception_handler));
	memset(&EG(user_error_handlers_error_reporting), 0, sizeof(EG(user_error_handlers_error_reporting)));
	memset(&EG(user_error_handlers), 0, sizeof(EG(user_error_handlers)));
	memset(&EG(user_exception_handlers), 0, sizeof(EG(user_exception_handlers)));
	EG(objects_store).object_buckets = NULL;
	EG(objects_store).top = 1;
	EG(error_handling) = EH_NORMAL;
	EG(exception) = NULL;
''', 2)

# main.c: superglobais e modules_activated
sub('main/main.c', '''			zval_ptr_dtor(&PG(http_globals)[i]);
''', '''			zval_ptr_dtor(&PG(http_globals)[i]);
			/* Backport CVE-2026-109619: pode ser acessado antes de php_request_startup() */
			ZVAL_UNDEF(&PG(http_globals)[i]);
''', -1)
insere_apos_regex('main/main.c', r'\n\tPHP_INI_ENTRY\("max_file_uploads",[^\n]*\n', '\tPHP_INI_ENTRY("max_multipart_body_parts",\t"-1",\t\tPHP_INI_SYSTEM|PHP_INI_PERDIR,\t\tNULL)\n')

# zend_llist: zerar head/tail
sub('Zend/zend_llist.c', '''		current = next;
	}

	l->count = 0;
}''', '''		current = next;
	}

	l->head  = NULL;
	l->tail  = NULL;
	l->count = 0;
}''')

# rfc1867: guardar so headers usados + limite de partes
sub('main/rfc1867.c', '''			*value = '\\0';
			do { value++; } while (isspace(*value));

			key = estrdup(line);
			smart_string_appends(&buf_value, value);
''', '''			*value = '\\0';

			/* Backport: manter so cabecalhos usados, ignorar duplicados */
			if ((strcasecmp(line, "Content-Disposition") && strcasecmp(line, "Content-Type"))
					|| php_mime_get_hdr_value(*header, line)) {
				key = NULL;
			} else {
				key = estrdup(line);
				do { value++; } while (isspace((unsigned char)*value));
				smart_string_appends(&buf_value, value);
			}
''')
# declarar php_mime_get_hdr_value antes de multipart_buffer_headers
sub('main/rfc1867.c', '''/* parse headers */
static int multipart_buffer_headers(''', '''static char *php_mime_get_hdr_value(zend_llist header, char *key);

/* parse headers */
static int multipart_buffer_headers(''')

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
				php_error_docref(NULL, E_WARNING, "Multipart body parts limit exceeded %d. To increase the limit change max_multipart_body_parts in php.ini.", body_parts_limit);
				goto fileupload_done;
			}
''')

# 1b) PR #1: "Possible integer overflow" e Balloc sem bailout, como no commit oficial
#     712e60f9ed (zend_alloc.c, zend_hash.c, zend_multiply.h -> safe_emalloc, zend_strtod.c)
for arq in ('Zend/zend_alloc.c', 'Zend/zend_hash.c', 'Zend/zend_multiply.h'):
    sub(arq, 'zend_error_noreturn(E_ERROR, "Possible integer overflow in ',
        'zend_mm_safe_error_ex("Possible integer overflow in ', -1)
sub('Zend/zend_strtod.c', 'zend_error_noreturn(E_ERROR, "Balloc() failed to allocate memory");',
    'zend_mm_safe_error_ex("Balloc() failed to allocate memory");', 2)

rodada('2')
# 8) CVE-2026-126714 (GHSA-fm2m-fjf5-v3cp): sessao 'files' sempre truncada antes de gravar
#    (upstream e2d3cee9ad). Escrita interrompida nao deixa mais sufixo da sessao antiga.
sub('ext/session/mod_files.c', '''	/* Truncate file if the amount of new data is smaller than the existing data set. */
	if (ZSTR_LEN(val) < data->st_size) {
		php_ignore_value(ftruncate(data->fd, 0));
	}
''', '''	/* Backport CVE-2026-126714: truncar SEMPRE antes de gravar; falhou, aborta */
	if (ftruncate(data->fd, 0) != 0) {
		php_error_docref(NULL, E_WARNING, "ftruncate() failed: %s (%d)", strerror(errno), errno);
		return FAILURE;
	}
''')

# 9) CVE-2026-129496 (GHSA-gr4f-wgx5-jpfv): timestamp do error_log em UTC fora de request ativo
#    (upstream cb20015e04). Evita usar o cache de timezone liberado no startup.
sub('main/main.c', '''#ifdef ZTS
			if (!php_during_module_startup()) {
				error_time_str = php_format_date("d-M-Y H:i:s e", 13, error_time, 1);
			} else {
				error_time_str = php_format_date("d-M-Y H:i:s e", 13, error_time, 0);
			}
#else
			error_time_str = php_format_date("d-M-Y H:i:s e", 13, error_time, 1);
#endif
''', '''			/* Backport CVE-2026-129496: hora local so com request ativo; senao UTC */
			error_time_str = php_format_date("d-M-Y H:i:s e", 13, error_time, PG(modules_activated) && EG(active));
''')

print("ok")
