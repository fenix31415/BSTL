struct BSTArrayBase
{
  uint32 size;
};

// --- ALLOCATORS --- //

struct __declspec(align(8)) BSTArrayHeapAllocator
{
  char *data;
  uint32 capacity;
  uint32 padC;
};

struct ScrapHeap;

struct __declspec(align(8)) BSScrapArrayAllocator
{
  ScrapHeap *heap;
  char *data;
  uint32 capacity;
  uint32 pad14;
};

union BSTSmallArrayHeapAllocator::Data
{
  char* *heap;
  char local[8];
};

struct __declspec(align(8)) BSTSmallArrayHeapAllocator
{
  uint32 capacity_n_flag;
  uint32 pad4;
  BSTSmallArrayHeapAllocator::Data data;
};

// ^^^ ALLOCATORS ^^^ //

// --- ARRAYS --- //

struct __declspec(align(8)) BSTArray
{
  BSTArrayHeapAllocator allocator;
  BSTArrayBase base;
  uint32 pad14;
};

struct __declspec(align(8)) BSScrapArray
{
  BSScrapArrayAllocator allocator;
  BSTArrayBase base;
};

struct __declspec(align(8)) BSTSmallArray
{
  BSTSmallArrayHeapAllocator allocator;
  BSTArrayBase base;
  uint32 pad14;
};

// ^^^ ARRAYS ^^^ //



// --- BSTArrayAllocatorFunctors --- //

struct BSTArrayBase::IAllocatorFunctor;

struct __declspec(align(8)) BSTArrayBase::IAllocatorFunctor::VFTable
{
  bool (*Allocate)(BSTArrayBase::IAllocatorFunctor *functor, uint32 num, uint32 elemSize);
  bool (*Reallocate)(BSTArrayBase::IAllocatorFunctor *functor, uint32 minNewSizeInItems, uint32 frontCopyCount, uint32 shiftCount, uint32 backCopyCount, uint32 elemSize);
  void (*Deallocate)(BSTArrayBase::IAllocatorFunctor *functor);
  BSTArrayBase::IAllocatorFunctor *(*dtor)(BSTArrayBase::IAllocatorFunctor *functor, char a2);
};

struct __declspec(align(8)) BSTArrayBase::IAllocatorFunctor
{
  BSTArrayBase::IAllocatorFunctor::VFTable *vtbl;
};

struct BSTArrayAllocatorFunctor_BSTArrayHeapAllocator_::VFTable
{
  bool (*Allocate)(BSTArrayAllocatorFunctor_BSTArrayHeapAllocator_ *functor, uint32 num, uint32 elemSize);
  bool (*Reallocate)(BSTArrayAllocatorFunctor_BSTArrayHeapAllocator_ *functor, uint32 minNewSizeInItems, uint32 frontCopyCount, uint32 shiftCount, uint32 backCopyCount, uint32 elemSize);
  void (*Deallocate)(BSTArrayAllocatorFunctor_BSTArrayHeapAllocator_ *functor);
  BSTArrayAllocatorFunctor_BSTArrayHeapAllocator_ *(*dtor)(BSTArrayAllocatorFunctor_BSTArrayHeapAllocator_ *functor, char a2);
};

struct __declspec(align(8)) BSTArrayAllocatorFunctor_BSTArrayHeapAllocator_
{
  BSTArrayAllocatorFunctor_BSTArrayHeapAllocator_::VFTable *vtbl;
  BSTArrayHeapAllocator* allocator;
};

struct BSTArrayAllocatorFunctor_BSScrapArrayAllocator_::VFTable
{
  bool (*Allocate)(BSTArrayAllocatorFunctor_BSScrapArrayAllocator_ *functor, uint32 num, uint32 elemSize);
  bool (*Reallocate)(BSTArrayAllocatorFunctor_BSScrapArrayAllocator_ *functor, uint32 minNewSizeInItems, uint32 frontCopyCount, uint32 shiftCount, uint32 backCopyCount, uint32 elemSize);
  void (*Deallocate)(BSTArrayAllocatorFunctor_BSScrapArrayAllocator_ *functor);
  BSTArrayAllocatorFunctor_BSScrapArrayAllocator_ *(*dtor)(BSTArrayAllocatorFunctor_BSScrapArrayAllocator_ *functor, char a2);
};

struct __declspec(align(8)) BSTArrayAllocatorFunctor_BSScrapArrayAllocator_
{
  BSTArrayAllocatorFunctor_BSScrapArrayAllocator_::VFTable *vtbl;
  BSScrapArrayAllocator* allocator;
};

// ^^^ BSTArrayAllocatorFunctors ^^^ //

