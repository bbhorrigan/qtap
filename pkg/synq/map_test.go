package synq

import (
	"reflect"
	"sync"
	"testing"
)

func TestMap_StoreLoad(t *testing.T) {
	cmap := NewMap[string, int]()
	cmap.Store("one", 1)
	if value, ok := cmap.Load("one"); !ok || value != 1 {
		t.Errorf("expected 1, got %d", value)
	}
}

func TestMap_Len(t *testing.T) {
	cmap := NewMap[string, int]()
	cmap.Store("one", 1)
	if value := cmap.Len(); value != 1 {
		t.Errorf("expected 1, got %d", value)
	}
}

func TestMap_Concurrency(t *testing.T) {
	cmap := NewMap[int, int]()
	wg := sync.WaitGroup{}
	wg.Add(100)

	for i := range 50 {
		go func(i int) {
			defer wg.Done()
			cmap.Store(i, i*2)
		}(i)
		go func(i int) {
			defer wg.Done()
			if value, ok := cmap.Load(i); ok && value != i*2 {
				t.Errorf("expected %d, got %d", i*2, value)
			}
		}(i)
	}

	wg.Wait()
}

func TestMap_Delete(t *testing.T) {
	cmap := NewMap[string, int]()
	cmap.Store("one", 1)
	cmap.Delete("one")
	if _, ok := cmap.Load("one"); ok {
		t.Errorf("expected 'one' to be deleted")
	}
}

func TestMap_NonExistentKey(t *testing.T) {
	cmap := NewMap[string, int]()
	if _, ok := cmap.Load("nonexistent"); ok {
		t.Errorf("expected 'nonexistent' key to not exist")
	}
}

func TestMap_Reset(t *testing.T) {
	cmap := NewMap[string, int]()
	cmap.Store("one", 1)
	cmap.Reset()
	if _, ok := cmap.Load("one"); ok {
		t.Errorf("expected 'one' to be deleted")
	}
}

func TestMap_LoadOrInsert(t *testing.T) {
	tests := []struct {
		name        string
		initialMap  map[string]int
		key         string
		value       int
		wantActual  int
		wantLoaded  bool
		wantMapSize int
	}{
		{
			name:        "Insert new key-value pair",
			initialMap:  map[string]int{},
			key:         "newKey",
			value:       42,
			wantActual:  42,
			wantLoaded:  false,
			wantMapSize: 1,
		},
		{
			name:        "Load existing key",
			initialMap:  map[string]int{"existingKey": 10},
			key:         "existingKey",
			value:       20,
			wantActual:  10,
			wantLoaded:  true,
			wantMapSize: 1,
		},
		{
			name:        "Insert into non-empty map",
			initialMap:  map[string]int{"key1": 1, "key2": 2},
			key:         "key3",
			value:       3,
			wantActual:  3,
			wantLoaded:  false,
			wantMapSize: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := &Map[string, int]{
				m: tt.initialMap,
			}

			actual, loaded := cm.LoadOrInsert(tt.key, tt.value)

			if actual != tt.wantActual {
				t.Errorf("LoadOrInsert() actual = %v, want %v", actual, tt.wantActual)
			}
			if loaded != tt.wantLoaded {
				t.Errorf("LoadOrInsert() loaded = %v, want %v", loaded, tt.wantLoaded)
			}
			if len(cm.m) != tt.wantMapSize {
				t.Errorf("Map size after LoadOrInsert() = %v, want %v", len(cm.m), tt.wantMapSize)
			}
			if !reflect.DeepEqual(cm.m[tt.key], tt.wantActual) {
				t.Errorf("Map value after LoadOrInsert() = %v, want %v", cm.m[tt.key], tt.wantActual)
			}
		})
	}
}

func TestIter(t *testing.T) {
	t.Run("Empty Map", func(t *testing.T) {
		cm := NewMap[int, string]()
		count := 0
		cm.Iter(func(key int, value string) bool {
			count++
			return true
		})
		if count != 0 {
			t.Errorf("Expected 0 iterations, got %d", count)
		}
	})

	t.Run("Iterate All Elements", func(t *testing.T) {
		cm := NewMap[int, string]()
		cm.Store(1, "one")
		cm.Store(2, "two")
		cm.Store(3, "three")

		seen := make(map[int]string)
		cm.Iter(func(key int, value string) bool {
			seen[key] = value
			return true
		})

		if len(seen) != 3 {
			t.Errorf("Expected 3 elements, got %d", len(seen))
		}
		for k, v := range seen {
			if cmv, _ := cm.Load(k); cmv != v {
				t.Errorf("Mismatch for key %d: expected %s, got %s", k, cmv, v)
			}
		}
	})

	t.Run("Early Termination", func(t *testing.T) {
		cm := NewMap[int, string]()
		for i := range 10 {
			cm.Store(i, string(rune('a'+i)))
		}

		count := 0
		cm.Iter(func(key int, value string) bool {
			count++
			return count < 5
		})

		if count != 5 {
			t.Errorf("Expected 5 iterations before termination, got %d", count)
		}
	})

	t.Run("Concurrent Modification", func(t *testing.T) {
		cm := NewMap[int, string]()
		for i := range 100 {
			cm.Store(i, string(rune('a'+i%26)))
		}

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			cm.Iter(func(key int, value string) bool {
				if key%10 == 0 {
					cm.Delete(key)
				}
				return true
			})
		}()

		go func() {
			defer wg.Done()
			for i := 100; i < 200; i++ {
				cm.Store(i, string(rune('a'+i%26)))
			}
		}()

		wg.Wait()

		finalLen := cm.Len()
		if finalLen < 180 || finalLen > 200 {
			t.Errorf("Expected between 180 and 200 elements after concurrent modification, got %d", finalLen)
		}

		// Verify that all elements are within the expected range
		cm.Iter(func(key int, value string) bool {
			if key < 0 || key >= 200 {
				t.Errorf("Unexpected key found: %d", key)
			}
			return true
		})
	})

	t.Run("Large Map", func(t *testing.T) {
		cm := NewMap[int, int]()
		const size = 1000000

		for i := range size {
			cm.Store(i, i)
		}

		count := 0
		cm.Iter(func(key int, value int) bool {
			count++
			return true
		})

		if count != size {
			t.Errorf("Expected %d iterations for large map, got %d", size, count)
		}
	})
}

func TestMap_Copy(t *testing.T) {
	t.Run("Copy", func(t *testing.T) {
		// Initialize a map with string keys and int values
		originalMap := map[string]int{"a": 1, "b": 2, "c": 3}

		cm := NewMap[string, int]()
		for k, v := range originalMap {
			cm.Store(k, v)
		}

		// Copy the map using copyMap
		copiedMap := cm.Copy()

		// Verify that the copied map has the same elements as the original
		if len(copiedMap) != len(originalMap) {
			t.Errorf("Copied map length %d does not match original map length %d", len(copiedMap), len(originalMap))
		}

		// Check individual elements
		for key, origValue := range originalMap {
			if copiedValue, ok := copiedMap[key]; !ok || copiedValue != origValue {
				t.Errorf("Key %s, expected copied value %d, got %d", key, origValue, copiedValue)
			}
		}

		// Modify the original map and ensure the copied map is not affected
		originalMap["a"] = 100
		if copiedMap["a"] == 100 {
			t.Errorf("Copied map value should not change when original map is modified")
		}
	})

	t.Run("Copy with reference types", func(t *testing.T) {
		// Initialize a map with slices as values (reference type)
		originalMap := map[string][]int{"x": {1, 2, 3}}

		cm := NewMap[string, []int]()
		for k, v := range originalMap {
			cm.Store(k, v)
		}

		// Copy the map
		copiedMap := cm.Copy()

		// Modify the slice in the original map, if it exists
		if slice, ok := originalMap["x"]; ok && len(slice) > 0 {
			originalMap["x"][0] = 100
		} else {
			t.Errorf("Original map does not contain expected key 'x' or slice is empty")
			return
		}

		// Check if the copied map's slice reflects the change
		if copiedSlice, ok := copiedMap["x"]; ok && len(copiedSlice) > 0 {
			if copiedSlice[0] != 100 {
				t.Errorf("Copied map's slice should reflect changes in the original map's slice elements")
			}
		} else {
			t.Errorf("Copied map does not contain expected key 'x' or slice is empty")
		}
	})
}
