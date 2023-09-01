/**
 * python与c交互
 * gcc -shared -o foo.so foo.c -lpython3.10
 */
// 1. 必须先定义PY_SSIZE_T_CLEAN和include Python.h
#define PY_SSIZE_T_CLEAN
#include <python3.10/Python.h>

// 2. 定义函数，注意其中的PyObject，PyLong_FromLong等对象
static PyObject *foo_add(PyObject *self, PyObject *args)
{
	int i, j, result;
	int flag = PyArg_ParseTuple(args, "ll:foo_add", &i, &j);
	if (!flag)
		return NULL;
	result = i + j;
	return PyLong_FromLong(result);
}

// 3. 定义模块包含的函数
static PyMethodDef FooMethods[] = {
	{
		"foo_add",			  // Python function name
		(PyCFunction)foo_add, // C implenmentation function name
		METH_VARARGS,
		PyDoc_STR("simple add use Python.h") // doc object
	},
	{NULL, NULL} // sentinel
};

// 4. 定义模块信息
PyDoc_STRVAR(foo_doc, "simple try of Python.h");
static struct PyModuleDef FooModule = {
	PyModuleDef_HEAD_INIT, // PyModuleDef_Base m_base
	"foo",				   // const char *m_name 模块名称
	foo_doc,			   // const char *m_doc 文档
	1,					   // Py_ssize_t m_size 可被重新初始化的次数，-1代表为拥有全局状态，但是不支持子解释器运行，如果只是自娱自乐的拓展，建议无脑填1
	FooMethods,			   // PyMethodDef *m_methods 方法集合
	NULL,				   // PyModuleDef_Slot *m_slots 多段初始化的槽序列，非多段初始化下，必须设成NULL
	NULL,				   // traverseproc m_traverse GC遍历时调用的遍历函数，如果m_size>0，必须设成NULL，因为此时该函数不会被调用
	NULL,				   // inquiry m_clear GC清除模块时运行的清除函数，如果m_size>0，必须设成NULL，因为此时该函数不会被调用
	NULL				   // freefunc m_free 模块被析构时被调用的函数，如果m_size>0，必须设成NULL，因为此时该函数不会被调用
};

// 5. 初始化模块, 注意函数的签名
PyMODINIT_FUNC PyInit_foo(void)
{
	return PyModuleDef_Init(&FooModule);
}