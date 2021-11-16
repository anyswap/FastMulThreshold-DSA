/*
 *  Copyright (C) 2020-2021  AnySwap Ltd. All rights reserved.
 *  Copyright (C) 2020-2021  haijun.cai@anyswap.exchange
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the Apache License, Version 2.0.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

// Package common  Self encapsulated list structure supporting concurrent operation 
package common

import (
	"container/list"
	"sync"
)

// Queue list + sync mutex
type Queue struct {
	l *list.List
	m sync.Mutex
}

// NewQueue new Queue
func NewQueue() *Queue {
	return &Queue{l: list.New()}
}

// PushBack put value to Queue
func (q *Queue) PushBack(v interface{}) {
	if v == nil {
		return
	}
	q.m.Lock()
	defer q.m.Unlock()
	q.l.PushBack(v)
}

// Front get front element 
func (q *Queue) Front() *list.Element {
	q.m.Lock()
	defer q.m.Unlock()
	return q.l.Front()
}

// Remove remove element
func (q *Queue) Remove(e *list.Element) {
	if e == nil {
		return
	}
	q.m.Lock()
	defer q.m.Unlock()
	q.l.Remove(e)
}

// Len get the len of Queue
func (q *Queue) Len() int {
	q.m.Lock()
	defer q.m.Unlock()
	return q.l.Len()
}

// InsertBefore insert value before element e
func (q *Queue) InsertBefore(v interface{}, e *list.Element) {
	q.m.Lock()
	defer q.m.Unlock()
	if e == nil {
	    return
	}

	q.l.InsertBefore(v, e)
}

