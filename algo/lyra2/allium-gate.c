#include "allium-gate.h"

__thread uint64_t* allium_wholeMatrix;

void allium_set_target( struct work* work, double job_diff )
{
 work_set_target( work, job_diff / (256.0 * opt_diff_factor) );
}

bool allium_thread_init()
{
   const int64_t ROW_LEN_INT64 = BLOCK_LEN_INT64 * 4; // nCols
   const int64_t ROW_LEN_BYTES = ROW_LEN_INT64 * 8;

   int i = (int64_t)ROW_LEN_BYTES * 4; // nRows;
   allium_wholeMatrix = _mm_malloc( i, 64 );
#if defined (ALLIUM_4WAY)
   init_allium_4way_ctx();;
#else
   init_allium_ctx();
#endif
   return allium_wholeMatrix;
}

bool register_allium_algo( algo_gate_t* gate )
{
#if defined (allium_4WAY)
  gate->scanhash  = (void*)&scanhash_allium_4way;
  gate->hash      = (void*)&allium_4way_hash;
#else
  gate->scanhash  = (void*)&scanhash_allium;
  gate->hash      = (void*)&allium_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | SSE42_OPT | AVX2_OPT;
  gate->miner_thread_init = (void*)&allium_thread_init;
  gate->set_target        = (void*)&allium_set_target;
  return true;
};


