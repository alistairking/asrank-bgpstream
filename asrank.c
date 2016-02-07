#include <assert.h>
#include <bgpstream.h>
#include <khash.h>
#include <stdio.h>

typedef struct asr_key {

  char project[128];
  char collector[128];
  bgpstream_addr_storage_t peer;
  bgpstream_pfx_storage_t pfx;
  bgpstream_as_path_t *path;

} asr_key_t;

#define asr_hash(key) (bgpstream_pfx_storage_hash((bgpstream_pfx_storage_t*)&((key).pfx)))

#define asr_equal(a, b) (strcmp(a.project, b.project)==0 && \
                         strcmp(a.collector, b.collector)==0 && \
                         bgpstream_addr_storage_equal(&a.peer, &b.peer) && \
                         bgpstream_pfx_storage_equal(&a.pfx, &b.pfx) && \
                         bgpstream_as_path_equal(a.path, b.path))

KHASH_INIT(asr_hash, asr_key_t, uint8_t, 1, asr_hash, asr_equal);

int main(int argc, char **argv)
{
  if (argc < 3) {
    fprintf(stderr, "Usage: asrank begin end [collector]\n");
    exit(-1);
  }

  int start = atoi(argv[1]);
  int end = atoi(argv[2]);
  char *collector = NULL;
  if (argc > 3) {
    collector = argv[3];
  }

  bgpstream_t *bs = bgpstream_create();
  bgpstream_record_t *rec = bgpstream_record_create();

  bgpstream_elem_t * elem = NULL;

  khash_t(asr_hash) *hash = kh_init(asr_hash);
  khiter_t k;
  int khret;

  int cnt = 0;

  asr_key_t findme;

  bgpstream_add_interval_filter(bs, start, end);

  bgpstream_add_filter(bs, BGPSTREAM_FILTER_TYPE_PROJECT, "routeviews");
  bgpstream_add_filter(bs, BGPSTREAM_FILTER_TYPE_PROJECT, "ris");

  if (collector != NULL) {
    bgpstream_add_filter(bs, BGPSTREAM_FILTER_TYPE_COLLECTOR, collector);
  }

  bgpstream_add_rib_period_filter(bs, 86400);

  bgpstream_add_filter(bs, BGPSTREAM_FILTER_TYPE_RECORD_TYPE, "ribs");

  bgpstream_start(bs);

  while(bgpstream_get_next_record(bs, rec) > 0) {
    if (rec->status != BGPSTREAM_RECORD_STATUS_VALID_RECORD) {
      continue;
    }

    strncpy(findme.collector, rec->attributes.dump_collector, 128);
    strncpy(findme.project, rec->attributes.dump_project, 128);

    while((elem = bgpstream_record_get_next_elem(rec)) != NULL) {

      memcpy(&findme.peer, &elem->peer_address, sizeof(bgpstream_addr_storage_t));

      memcpy(&findme.pfx, &elem->prefix, sizeof(bgpstream_pfx_storage_t));

      findme.path = bgpstream_as_path_create();
      bgpstream_as_path_copy(findme.path, elem->aspath);

      if ((k = kh_get(asr_hash, hash, findme)) == kh_end(hash)) {
        k = kh_put(asr_hash, hash, findme, &khret);
        kh_val(hash, k) = 1;
      } else {
        kh_val(hash, k)++;
        bgpstream_as_path_destroy(findme.path);
      }

      if ((cnt % 1000000) == 0) {
        fprintf(stderr, "Processed %d elems\n", cnt);
      }
      cnt++;
    }
  }

  char pfx_buf[1024];
  char path_buf[1024];
  char peer_buf[1024];

  for (k = kh_begin(hash); k < kh_end(hash); k++) {
    if (!kh_exist(hash, k)) {
      continue;
    }
    asr_key_t *key = &kh_key(hash, k);
    bgpstream_pfx_snprintf(pfx_buf, 1024, (bgpstream_pfx_t *)&key->pfx);
    bgpstream_as_path_snprintf(path_buf, 1024, key->path);
    bgpstream_addr_ntop(peer_buf, 1024, (bgpstream_ip_addr_t *)&key->peer);
    // project/collector|cnt|path|pfx|x|peer
    fprintf(stdout, "%s/%s|%d|%s|%s|x|%s\n",
            key->project, key->collector,
            kh_val(hash, k),
            path_buf, pfx_buf, peer_buf);
  }

  // TODO free the hash

  bgpstream_record_destroy(rec);
  bgpstream_destroy(bs);
}
