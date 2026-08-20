package sqsdriver

import "context"

func (driver *Driver) begin(ctx context.Context) (func(), error) {
	if ctx == nil {
		return nil, ErrInput
	}
	if ctx.Err() != nil {
		return nil, ErrCanceled
	}
	if !driver.usable() {
		return nil, ErrInput
	}
	driver.lifecycleMu.Lock()
	defer driver.lifecycleMu.Unlock()
	if driver.draining {
		return nil, ErrDraining
	}
	driver.inflight.Add(1)
	return driver.inflight.Done, nil
}

func (driver *Driver) Drain(ctx context.Context) error {
	if ctx == nil || !driver.usable() {
		return ErrInput
	}
	driver.lifecycleMu.Lock()
	driver.draining = true
	driver.lifecycleMu.Unlock()

	done := make(chan struct{})
	go func() {
		driver.inflight.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ErrCanceled
	}
}
