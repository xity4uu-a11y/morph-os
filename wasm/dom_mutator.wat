;; morph-os Native WebAssembly 1.0 DOM & Buffer Mutation Kernel
;; Compiles cleanly to wasm/dom_mutator.wasm via `node scripts/compile-wasm.mjs`.
;; Zero external host imports; operates purely on exported linear memory.

(module
  ;; 1 page = 64 KiB exported linear memory (growable by host as needed)
  (memory (export "memory") 1)

  ;; Count byte-subsequence matches (e.g., "<tr", "<td", "<table") in UTF-8 DOM buffers.
  (func (export "count_tag_matches")
    (param $ptr i32) (param $len i32) (param $needle_ptr i32) (param $needle_len i32)
    (result i32)
    (local $i i32)
    (local $j i32)
    (local $count i32)
    (local $limit i32)
    (local $matched i32)

    ;; Guard invalid or oversized needles
    (if (i32.le_s (local.get $needle_len) (i32.const 0))
      (then (return (i32.const 0))))
    (if (i32.gt_s (local.get $needle_len) (local.get $len))
      (then (return (i32.const 0))))

    (local.set $limit (i32.sub (local.get $len) (local.get $needle_len)))
    (local.set $i (i32.const 0))
    (local.set $count (i32.const 0))

    (block $outer_break
      (loop $outer
        (br_if $outer_break (i32.gt_s (local.get $i) (local.get $limit)))

        (local.set $j (i32.const 0))
        (local.set $matched (i32.const 1))

        (block $inner_break
          (loop $inner
            (br_if $inner_break (i32.ge_s (local.get $j) (local.get $needle_len)))
            (if
              (i32.ne
                (i32.load8_u (i32.add (local.get $ptr) (i32.add (local.get $i) (local.get $j))))
                (i32.load8_u (i32.add (local.get $needle_ptr) (local.get $j))))
              (then
                (local.set $matched (i32.const 0))
                (br $inner_break)))
            (local.set $j (i32.add (local.get $j) (i32.const 1)))
            (br $inner)))

        (if (local.get $matched)
          (then
            (local.set $count (i32.add (local.get $count) (i32.const 1)))))

        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $outer)))

    (local.get $count))

  ;; In-place linear-memory ASCII digit masker ('0'..'9' -> replacement byte).
  ;; Returns total masked byte count.
  (func (export "mask_ascii_digits")
    (param $ptr i32) (param $len i32) (param $replacement i32)
    (result i32)
    (local $i i32)
    (local $count i32)
    (local $ch i32)

    (local.set $i (i32.const 0))
    (local.set $count (i32.const 0))

    (block $done
      (loop $scan
        (br_if $done (i32.ge_s (local.get $i) (local.get $len)))
        (local.set $ch (i32.load8_u (i32.add (local.get $ptr) (local.get $i))))
        (if
          (i32.and
            (i32.ge_u (local.get $ch) (i32.const 48))
            (i32.le_u (local.get $ch) (i32.const 57)))
          (then
            (i32.store8 (i32.add (local.get $ptr) (local.get $i)) (local.get $replacement))
            (local.set $count (i32.add (local.get $count) (i32.const 1)))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $scan)))

    (local.get $count))

  ;; Deterministic 32-bit FNV-1a digest over a UTF-8 buffer in linear memory.
  (func (export "fnv1a_hash")
    (param $ptr i32) (param $len i32)
    (result i32)
    (local $i i32)
    (local $hash i32)

    (local.set $i (i32.const 0))
    (local.set $hash (i32.const -2128831035)) ;; 0x811c9dc5

    (block $done
      (loop $step
        (br_if $done (i32.ge_s (local.get $i) (local.get $len)))
        (local.set $hash
          (i32.mul
            (i32.xor
              (local.get $hash)
              (i32.load8_u (i32.add (local.get $ptr) (local.get $i))))
            (i32.const 16777619))) ;; 0x01000193
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $step)))

    (local.get $hash))

  ;; In-place ASCII whitespace normalizer: collapses runs of space/tab/CR/LF into single spaces
  ;; and trims leading/trailing whitespace. Returns normalized byte length.
  (func (export "normalize_whitespace")
    (param $ptr i32) (param $len i32)
    (result i32)
    (local $r i32)
    (local $w i32)
    (local $in_ws i32)
    (local $ch i32)
    (local $is_ws i32)

    (local.set $r (i32.const 0))
    (local.set $w (i32.const 0))
    (local.set $in_ws (i32.const 1))

    (block $done
      (loop $scan
        (br_if $done (i32.ge_s (local.get $r) (local.get $len)))
        (local.set $ch (i32.load8_u (i32.add (local.get $ptr) (local.get $r))))
        (local.set $is_ws
          (i32.or
            (i32.or
              (i32.eq (local.get $ch) (i32.const 32))
              (i32.eq (local.get $ch) (i32.const 9)))
            (i32.or
              (i32.eq (local.get $ch) (i32.const 10))
              (i32.eq (local.get $ch) (i32.const 13)))))

        (if (local.get $is_ws)
          (then
            (if (i32.eqz (local.get $in_ws))
              (then
                (i32.store8 (i32.add (local.get $ptr) (local.get $w)) (i32.const 32))
                (local.set $w (i32.add (local.get $w) (i32.const 1)))
                (local.set $in_ws (i32.const 1)))))
          (else
            (i32.store8 (i32.add (local.get $ptr) (local.get $w)) (local.get $ch))
            (local.set $w (i32.add (local.get $w) (i32.const 1)))
            (local.set $in_ws (i32.const 0))))

        (local.set $r (i32.add (local.get $r) (i32.const 1)))
        (br $scan)))

    ;; Trim single trailing space if present
    (if (i32.gt_s (local.get $w) (i32.const 0))
      (then
        (if
          (i32.eq
            (i32.load8_u (i32.add (local.get $ptr) (i32.sub (local.get $w) (i32.const 1))))
            (i32.const 32))
          (then
            (local.set $w (i32.sub (local.get $w) (i32.const 1)))))))

    (local.get $w))
)
