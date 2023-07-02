I have written a script that REs 3.5% of the Skyrim!
The game has 113614 functions, which is a lot to analyze manually. I noticed that the game uses template types for different kinds of arrays and hash-maps. Each type generates its own (almost identical) functions. For example, `BSTArray<int>` has the same `begin` function as `BSTArray<PlayerCharacter*>`. My script can automatically find over 4k such functions, and it can also determine their addresses, types, and create the structures they use.

This script can also help you with reverse-engineering new functions, as you can see the usage of functions related to arrays & maps. You can also see the types of local variables that are passed to the functions that my script identified. This can make your analysis more accurate and efficient.

It is for SSE and for IDA 7.6. I am afraid that it doesn't work with older versions, but I beieve that there is someone here who can port it to previous versions. Fortunately few functions are used while you run it. 


BACKUP DATABASE BEFORE USING!
(I always use Ctrl+Z and all fine, but just in case)

This script detects some functions for BSTArray, BSScrapArray, BSTSmallArray, BSTHashMap, BSTSet, BSTScrapHashMap.
It sets right signatures, name and also creates necessary structures. There is statistic below.

Setup:
  1. I am using some libs, so you probably need to install them:
     * pip install python-Levenshtein;
     * I believe thats all, but if you get import errors, probably you need to install something else.
  2. Unpack the archive next to the your database.
  3. Run IDA.
  4. File -> Script file -> BSTL.py.
  5. In python prompt type `run()` and press Enter.
  6. Wait untill script finished.
  7. Wait for the auto-analysis to finish.
  8. Many structs created (you can look at them in Structs window).
  9. Many functuins created, you can search for `BSTArray` or `BSTHashMap`, for example.

What next:
  * When you REing a function and see those new functions, you know the structure type and what happens at this call.
  * Some local variables also have rigth type.
  * You can look at those functions and jump to xrefs. This way you can find unexplored parts of structures, as well as global arrays/maps.

Brief explanation:
  There is a variable `action_mode`. You can find it and read comments near.
  In (default) ACTION_MODES_import mode, script reads BSTL_data.txt file, creates all needed structs and then set all found types.
  You can change mode if you want to port/just experiment.
  Some functions has skipped (mostly because of their count)
  Some functions have inacurrate signature (e.g. MapK4V12 instead of MapK4V8 (and 4 bytes of padding between them). I decided to have faster but less acurate algorithm in some places.
  You can use `create_typed-` and `create_sized-` functions directly from IDA to create and modify the Array/Map type you REd.

Here you can see statistic (function name and number of instances found):

STATS: (4020 total)
  BSTArray::end: 399
  BSTArray::begin: 397
  BSTArray::push_back: 325
  BSTArray::eraseMany: 251
  j_BSTArray::begin: 246
  j_BSTArray::end: 245
  BSTHashMap::get_free_entry: 239
  BSTHashMap::insert1: 233
  BSTHashMap::double: 233
  BSTHashMap::insert: 231
  BSTHashMap::begin: 145
  BSTHashMap::end: 145
  BSTArray::Resize: 113
  j_BSTHashMap::begin: 79
  j_BSTHashMap::end: 79
  BSScrapArray::begin: 53
  BSScrapArray::end: 53
  BSScrapArray::push_back: 49
  BSTArray::eraseAt: 37
  BSTScrapHashMap::insert1: 37
  BSTScrapHashMap::double: 37
  BSTArray::insert: 32
  BSTScrapHashMap::get_free_entry: 29
  BSTSmallArray::begin: 27
  BSTSmallArray::end: 27
  BSTArray::eraseVal: 22
  BSScrapArray::Resize: 20
  BSTScrapHashMap::insert: 20
  j_BSScrapArray::begin: 19
  j_BSScrapArray::end: 19
  BSScrapArray::reserve_push_backs2: 18
  BSTHashMap::find: 18
  j_BSTSmallArray::begin: 13
  j_BSTSmallArray::end: 13
  BSScrapArray::insert: 13
  BSTHashMap::find1: 12
  BSTArray::rbegin: 11
  BSTArray::rend: 10
  BSScrapArray::eraseMany: 8
  BSTSmallArray::Resize: 7
  BSTSet::insert1: 7
  BSTSet::double: 7
  BSTArray::reserve_push_backs: 5
  BSTSet::get_free_entry: 5
  BSTSet::insert: 5
  BSTHashMap::find2: 4
  BSTArrayHeapAllocator::Allocate: 1
  BSTArrayAllocatorFunctor_BSTArrayHeapAllocator_::Allocate: 1
  BSTArrayHeapAllocator::Reallocate: 1
  BSTArrayAllocatorFunctor_BSTArrayHeapAllocator_::Reallocate: 1
  BSTArrayHeapAllocator::Free: 1
  BSTArrayAllocatorFunctor_BSTArrayHeapAllocator_::Free: 1
  BSScrapArrayAllocator::Allocate: 1
  BSTArrayAllocatorFunctor_BSScrapArrayAllocator_::Allocate: 1
  BSScrapArrayAllocator::Reallocate: 1
  BSTArrayAllocatorFunctor_BSScrapArrayAllocator_::Reallocate: 1
  BSScrapArrayAllocator::Free: 1
  BSTArrayAllocatorFunctor_BSScrapArrayAllocator_::Free: 1
  BSTSmallArrayHeapAllocator::Allocate: 1
  BSTSmallArrayHeapAllocator::Reallocate: 1
  BSTSmallArrayHeapAllocator::Free: 1
  BSTArrayBase::reserve_push_back: 1
  BSTArrayBase::prepare_insert: 1
  BSTArrayBase::erase: 1
  BSTArrayBase::ctor: 1
  BSTArrayBase::clear: 1
  BSTArrayBase::reserve: 1
  BSScrapArray::eraseAt: 1
  BSScrapArray::reserve_push_backs: 1
