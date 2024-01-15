# mcap

### Example

```go
// listen on port 47019 for key payload
func main() {
	// ignore errors for now.
	ch := make(chan bsoncore.Value)
	go mcap.Listen(context.TODO(), "payload", 47019, ch)

	// start decoding payloads...
	payload := <-ch
}
```
