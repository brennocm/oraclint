package model

// Merge combines several config documents the way the node does when it is
// started with multiple -config flags: later files override earlier ones.
//
//   - tables are merged key by key;
//   - arrays of tables are merged element by element when elements carry an
//     identifying key: "ChainID" for chains ([[EVM]], [[Solana]], ...) and
//     "Name" for [[EVM.Nodes]]. Elements without a match are appended
//     (chainlink-evm EVMConfigs.SetFrom / EVMNodes.SetFrom);
//   - any other value, including plain arrays, is replaced.
//
// Every value keeps the Location of the file that set it, so findings point to
// the file that actually determines the effective value. The inputs are not
// modified.
func Merge(docs ...*Value) *Value {
	if len(docs) == 0 {
		return nil
	}
	out := clone(docs[0])
	for _, d := range docs[1:] {
		mergeInto(out, d)
	}
	return out
}

func mergeInto(dst, src *Value) {
	for key, s := range src.Table {
		d, exists := dst.Table[key]
		switch {
		case !exists:
			dst.Table[key] = clone(s)
		case d.Kind == TableValue && s.Kind == TableValue:
			mergeInto(d, s)
		case isTableArray(d) && isTableArray(s):
			mergeTableArrays(d, s)
		default:
			dst.Table[key] = clone(s)
		}
	}
}

func mergeTableArrays(dst, src *Value) {
	for _, s := range src.Array {
		if i := matchingElement(dst.Array, s); i >= 0 {
			mergeInto(dst.Array[i], s)
		} else {
			dst.Array = append(dst.Array, clone(s))
		}
	}
}

// matchingElement returns the index of the element of elems with the same
// identity as v, or -1.
func matchingElement(elems []*Value, v *Value) int {
	for _, idKey := range []string{"ChainID", "Name"} {
		id := v.Table[idKey]
		if id == nil || id.Kind != ScalarValue {
			continue
		}
		for i, e := range elems {
			other := e.Table[idKey]
			if other != nil && other.Kind == ScalarValue && other.Scalar == id.Scalar {
				return i
			}
		}
		return -1
	}
	return -1
}

func isTableArray(v *Value) bool {
	if v.Kind != ArrayValue || len(v.Array) == 0 {
		return false
	}
	for _, e := range v.Array {
		if e.Kind != TableValue {
			return false
		}
	}
	return true
}

func clone(v *Value) *Value {
	c := &Value{Kind: v.Kind, Scalar: v.Scalar, Loc: v.Loc}
	if v.Table != nil {
		c.Table = make(map[string]*Value, len(v.Table))
		for k, child := range v.Table {
			c.Table[k] = clone(child)
		}
	}
	if v.Array != nil {
		c.Array = make([]*Value, len(v.Array))
		for i, child := range v.Array {
			c.Array[i] = clone(child)
		}
	}
	return c
}
