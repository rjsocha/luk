package queue

// Watcher signals on C when an entry may have been committed into a watched
// queue directory. Signals coalesce: C holds at most one.
type Watcher struct {
	C    <-chan struct{}
	done chan struct{}
}

// Done is closed once the watcher stopped: its context ended or inotify
// failed.
func (w *Watcher) Done() <-chan struct{} { return w.done }
