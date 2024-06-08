# mcap

### Example

```go
// listen on port 27017 for the key called payload
func main() {
	ctx := context.TODO()

	// ignore errors for now.
	ch := make(chan bsoncore.Value)
	go mcap.Listen(ctx, "payload", 27017, ch)

	// start decoding payloads...
	payload := <-ch
}
```
