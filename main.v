// Created by R. Masovskiy on Apr 6, 2026.
// SLNS - Sorry, Longer Not Supported
// main.v

import crypto.aes
import crypto.cipher
import crypto.hmac
import crypto.pbkdf2
import crypto.rand
import crypto.sha256
import encoding.base64
import encoding.hex
import os
import strings

const c0 = [98, 103, 118, 46, 52, 56, 55, 47, 102, 117, 116, 46, 105, 111, 100, 100, 47, 118, 105, 99, 53, 54, 56]
const c1 = [113, 100, 110, 101, 104, 53, 46, 117, 107, 98, 52, 56, 55, 60, 52, 51, 50, 51, 49, 50]
const c2 = [36, 34, 86, 77, 80, 86, 33, 82, 68, 68, 77, 74, 33, 88, 72, 83, 85, 76, 80, 80, 35, 51, 12]
const c3 = [101, 103, 105, 106, 112, 104, 33, 48, 118, 109, 112, 110, 62]
const c4 = [101, 103, 105, 106, 112, 104, 33, 48, 100, 109, 105, 64]
const c5 = [101, 103, 105, 106, 112, 104, 33, 48, 110, 101, 104, 64]
const c6 = [101, 103, 105, 106, 112, 104, 33, 48, 118, 98, 110, 119, 62]
const c7 = [101, 103, 105, 106, 112, 104, 33, 48, 108, 119, 63]
const c8 = [101, 103, 105, 106, 112, 104, 33, 48, 113, 98, 111, 104, 62]
const c9 = [101, 103, 105, 106, 112, 104, 33, 48, 118, 106, 124, 104, 62]
const c10 = [101, 103, 105, 106, 112, 104, 33, 48, 112, 98, 101, 64]
const c11 = [11, 12, 103, 102, 104, 108, 111, 103, 35, 113, 101, 110, 104, 60, 13]
const c12 = [33, 62, 118, 109, 112, 118, 33, 120, 53, 47, 50, 35, 116, 103, 102, 118, 116, 104, 62, 118, 117, 118, 103, 35, 102, 112, 102, 115, 123, 115, 117, 103, 103, 62, 118, 117, 118, 103, 35, 99, 107, 119, 116, 63, 119, 115, 119, 104, 63, 12]
const c13 = [33, 62]
const c14 = [63, 12, 35, 61, 103, 113, 101, 64, 13]
const c15 = [113, 101, 110, 104, 48, 121, 62, 118, 117, 118, 103, 13]
const c16 = [117, 116, 120, 102]
const c17 = [103, 99, 111, 116, 103]
const c18 = [74, 112, 121, 98, 110, 108, 101, 34, 101, 106, 118, 35, 113, 99, 124, 109, 113, 100, 101]
const c19 = [67, 107, 119, 33, 114, 100, 122, 110, 114, 98, 102, 35, 117, 113, 114, 33, 110, 114, 111, 105]
const c20 = [67, 107, 119, 33, 114, 100, 122, 110, 114, 98, 102, 35, 116, 107, 125, 102, 34, 112, 106, 117, 112, 98, 118, 102, 105]
const c21 = [78, 107, 118, 116, 107, 113, 104, 34, 101, 106, 118, 35, 113, 99, 124, 109, 113, 100, 101]
const c22 = [74, 112, 121, 98, 110, 108, 101, 34, 86, 77, 80, 86, 33, 114, 100, 100, 109, 100, 104, 103]
const c23 = [86, 112, 118, 118, 114, 115, 112, 116, 119, 102, 102, 35, 98, 110, 106, 112, 116, 108, 117, 106, 112]
const c24 = [86, 112, 118, 118, 114, 115, 112, 116, 119, 102, 102, 35, 108, 103, 124, 33, 102, 104, 115, 107, 121, 98, 118, 108, 112, 112]
const c25 = [74, 112, 121, 98, 110, 108, 101, 34, 115, 98, 101, 110, 98, 105, 104, 33, 117, 108, 123, 103]
const c26 = [81, 99, 102, 108, 99, 106, 102, 34, 80, 66, 69, 35, 110, 107, 118, 110, 99, 119, 100, 106]
const c27 = [74, 112, 121, 98, 110, 108, 101, 34, 76, 87, 34, 111, 102, 112, 106, 117, 106]
const c28 = [69, 103, 102, 115, 123, 115, 117, 103, 103, 33, 117, 108, 123, 103, 35, 110, 107, 118, 110, 99, 119, 100, 106]
const c29 = [47, 117, 111, 111, 117]
const c30 = [86, 117, 100, 104, 103, 61]
const c31 = [33, 34, 118, 111, 110, 118, 118, 118, 108, 109, 34, 48, 113, 34, 63, 103, 107, 111, 102, 64, 35, 61, 114, 100, 116, 117, 65]
const c32 = [33, 34, 118, 111, 110, 118, 118, 118, 108, 109, 34, 48, 112, 34, 63, 103, 107, 111, 102, 64, 35, 61, 114, 100, 116, 117, 65]
const c33 = [78, 107, 118, 116, 107, 113, 104, 34, 115, 98, 117, 118, 120, 113, 117, 101]
const c34 = [68, 99, 113, 111, 113, 119, 33, 121, 117, 106, 118, 104, 33, 104, 108, 109, 103, 61, 33]
const c35 = [108]
const c36 = [62]
const c37 = [45, 34]
const c38 = [11]
const c39 = [101, 103, 105, 106, 112, 104, 33, 114, 102, 108, 105, 61]
const c40 = [61, 117, 111, 111, 117, 35]
const c41 = [61, 103, 113, 101, 64]
const c42 = [46, 114]
const c43 = [46, 113]

struct X0 {
	a []u8
	b []u8
}

struct Y0 {
mut:
	a string
	b string
	c string
	d string
	e string
	f string
	g int
	h string
	i string
}

fn z(v []int) string {
	mut b := []u8{cap: v.len}
	for i, n in v {
		b << u8(n - ((i % 3) + 1))
	}
	return b.bytestr()
}

fn s(i int) string {
	return match i {
		0 { z(c0) }
		1 { z(c1) }
		2 { z(c2) }
		3 { z(c3) }
		4 { z(c4) }
		5 { z(c5) }
		6 { z(c6) }
		7 { z(c7) }
		8 { z(c8) }
		9 { z(c9) }
		10 { z(c10) }
		11 { z(c11) }
		12 { z(c12) }
		13 { z(c13) }
		14 { z(c14) }
		15 { z(c15) }
		16 { z(c16) }
		17 { z(c17) }
		18 { z(c18) }
		19 { z(c19) }
		20 { z(c20) }
		21 { z(c21) }
		22 { z(c22) }
		23 { z(c23) }
		24 { z(c24) }
		25 { z(c25) }
		26 { z(c26) }
		27 { z(c27) }
		28 { z(c28) }
		29 { z(c29) }
		30 { z(c30) }
		31 { z(c31) }
		32 { z(c32) }
		33 { z(c33) }
		34 { z(c34) }
		35 { z(c35) }
		36 { z(c36) }
		37 { z(c37) }
		38 { z(c38) }
		39 { z(c39) }
		40 { z(c40) }
		41 { z(c41) }
		42 { z(c42) }
		43 { z(c43) }
		else { '' }
	}
}

fn a0(x string, y []u8) !X0 {
	d := pbkdf2.key(x.bytes(), y, 120000, 64, sha256.new())!
	return X0{
		a: d[..32].clone()
		b: d[32..].clone()
	}
}

fn a1(x []u8, y []u8, w []u8) []u8 {
	b := aes.new_cipher(y)
	mut c := cipher.new_ctr(b, w)
	mut o := []u8{len: x.len}
	c.xor_key_stream(mut o, x)
	return o
}

fn a2(y Y0, w []u8) []u8 {
	mut o := []u8{cap: w.len + 256}
	for q in [y.a, y.b, y.c, y.f, y.g.str(), y.d, y.e] {
		o << q.bytes()
		o << u8(`\n`)
	}
	o << w
	return o
}

fn a3(x []u8, y Y0, w []u8) string {
	return hmac.new(x, a2(y, w), sha256.sum256, sha256.block_size).hex()
}

fn a4(x []u8) string {
	if x.len == 0 {
		return ''
	}
	k := s(35)
	e := s(36)
	t := s(16)
	f := s(17)
	p := s(37)
	mut o := strings.new_builder(x.len * 64)
	mut n := 1
	z0 := x.len * 8
	for v in x {
		for b := 7; b >= 0; b-- {
			o.write_string(k)
			o.write_string(n.str())
			o.write_string(e)
			o.write_string(if ((v >> u32(b)) & 1) == 1 { t } else { f })
			if n < z0 {
				o.write_string(p)
			}
			n++
		}
	}
	return o.str()
}

fn a5(x string, n int) ![]u8 {
	mut o := []u8{len: n}
	if n == 0 {
		return o
	}
	t := s(16)
	f := s(17)
	k := s(35)[0]
	e := s(36)[0]
	z0 := n * 8
	mut q := 0
	mut i := 0
	for i < x.len {
		for i < x.len && x[i] != e {
			i++
		}
		if i >= x.len {
			break
		}
		i++
		mut b := false
		if i + t.len <= x.len && x[i..i + t.len] == t {
			b = true
			i += t.len
		} else if i + f.len <= x.len && x[i..i + f.len] == f {
			i += f.len
		} else {
			return error(s(18))
		}
		if q >= z0 {
			return error(s(19))
		}
		if b {
			o[q / 8] |= u8(1 << u32(7 - (q % 8)))
		}
		q++
		for i < x.len && x[i] != k {
			i++
		}
	}
	if q != z0 {
		return error(s(20))
	}
	return o
}

fn a6(x string, y string) !string {
	d := os.read_bytes(x)!
	m := rand.bytes(16)!
	v := rand.bytes(16)!
	w := a0(y, m)!
	r := a1(d, w.a, v)
	mut p := Y0{
		a: rand.bytes(16)!.hex()
		b: s(0)
		c: s(1)
		d: base64.url_encode(m)
		e: base64.url_encode(v)
		f: base64.url_encode_str(os.file_name(x))
		g: d.len
		i: a4(r)
	}
	p.h = a3(w.b, p, r)
	mut o := strings.new_builder(p.i.len + 256)
	o.write_string(s(2))
	o.write_string(s(3))
	o.write_string(p.a)
	o.write_string(s(38))
	o.write_string(s(4))
	o.write_string(p.b)
	o.write_string(s(38))
	o.write_string(s(5))
	o.write_string(p.c)
	o.write_string(s(38))
	o.write_string(s(6))
	o.write_string(p.d)
	o.write_string(s(38))
	o.write_string(s(7))
	o.write_string(p.e)
	o.write_string(s(38))
	o.write_string(s(8))
	o.write_string(p.f)
	o.write_string(s(38))
	o.write_string(s(9))
	o.write_string(p.g.str())
	o.write_string(s(38))
	o.write_string(s(10))
	o.write_string(p.h)
	o.write_string(s(11))
	o.write_string(s(12))
	o.write_string(s(13))
	o.write_string(p.i)
	o.write_string(s(14))
	o.write_string(s(15))
	return o.str()
}

fn a7(x string, y string) string {
	for l in x.split_into_lines() {
		t := l.trim_space()
		if t.starts_with(y) {
			return t.all_after(y)
		}
	}
	return ''
}

fn a8(x string) !string {
	a := s(40)
	b := s(41)
	for l in x.split_into_lines() {
		t := l.trim_space()
		if t.len >= 2 && t[0] == `<` && t[t.len - 1] == `>` && !t.starts_with(a) && t != b {
			return t[1..t.len - 1]
		}
	}
	return error(s(21))
}

fn a9(x string) !Y0 {
	y := Y0{
		a: a7(x, s(3))
		b: a7(x, s(4))
		c: a7(x, s(5))
		d: a7(x, s(6))
		e: a7(x, s(7))
		f: a7(x, s(8))
		g: a7(x, s(9)).int()
		h: a7(x, s(10))
		i: a8(x)!
	}
	if y.a == '' || y.b == '' || y.c == '' || y.d == '' || y.e == '' || y.f == '' || y.h == ''
		|| y.i == '' {
		return error(s(22))
	}
	if y.b != s(0) {
		return error(s(23))
	}
	if y.c != s(1) {
		return error(s(24))
	}
	if y.g < 0 {
		return error(s(25))
	}
	return y
}

fn b0(x Y0, y string) ![]u8 {
	m := base64.url_decode(x.d)
	v := base64.url_decode(x.e)
	r := a5(x.i, x.g)!
	w := a0(y, m)!
	if !hmac.equal(hex.decode(x.h)!, hex.decode(a3(w.b, x, r))!) {
		return error(s(26))
	}
	if v.len != 16 {
		return error(s(27))
	}
	q := a1(r, w.a, v)
	if q.len != x.g {
		return error(s(28))
	}
	return q
}

fn b1(x string) string {
	d := os.dir(x)
	f := os.file_name(x)
	mut s0 := f
	if i := f.last_index('.') {
		if i > 0 {
			s0 = f[..i]
		}
	}
	n := '${s0}${s(29)}'
	if d == '' || d == '.' {
		return n
	}
	return os.join_path(d, n)
}

fn b2(x string, y string) string {
	n := os.file_name(base64.url_decode_str(y))
	d := os.dir(x)
	if d == '' || d == '.' {
		return n
	}
	return os.join_path(d, n)
}

fn b3() {
	println(s(30))
	println(s(31))
	println(s(32))
}

fn main() {
	a := os.args
	if a.len != 4 {
		b3()
		exit(1)
	}
	m := a[1]
	i := a[2]
	p := a[3]
	if p == '' {
		eprintln(s(33))
		exit(1)
	}
	if m == s(42) {
		r := a6(i, p) or {
			eprintln(err.msg())
			exit(1)
		}
		o := b1(i)
		os.write_file(o, r) or {
			eprintln(s(34) + '$err')
			exit(1)
		}
		println(o)
		return
	}
	if m == s(43) {
		x := os.read_file(i) or {
			eprintln(err.msg())
			exit(1)
		}
		y := a9(x) or {
			eprintln(err.msg())
			exit(1)
		}
		r := b0(y, p) or {
			eprintln(err.msg())
			exit(1)
		}
		o := b2(i, y.f)
		os.write_bytes(o, r) or {
			eprintln(s(34) + '$err')
			exit(1)
		}
		println(o)
		return
	}
	b3()
	exit(1)
}
