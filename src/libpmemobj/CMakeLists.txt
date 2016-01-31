set(pmemobj_SOURCE 
	cuckoo.c
	list.c
	heap.c
	sync.c
	tx.c
	libpmemobj.c
	ctree.c
	bucket.c
	lane.c
	redo.c
	pmalloc.c
	obj.c
)

set(pmemobj_HEADERS ../include/libpmemobj.h)
set(pmemobj_VERSION_MAJOR 1)
set(pmemobj_VERSION_MINOR 0)
set(pmemobj_VERSION_PATCH 0)
LIBRARY(pmemobj)
