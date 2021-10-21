__libc_free (void *mem){
    p = mem2chunk (mem);
    if (chunk_is_mmapped (p)) -> ...
    MAYBE_INIT_TCACHE ();
    ar_ptr = arena_for_chunk (p);
    _int_free (ar_ptr, p, 0);
}
_int_free (mstate av, mchunkptr p, int have_lock){
	size = chunksize (p);
    check_pointer;
    check_size;
    check_inuse_chunk(av, p);
    if USE_TCACHE {
        tc_idx = csize2tidx (size);
        if (tcache 
            && tc_idx < mp_.tcache_bins 
            && tcache->counts[tc_idx] < mp_.tcache_count
           ){tcache_put(p, tc_idx); return;}
    }
    ... ;
    ... ;
    ... ;
}