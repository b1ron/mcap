# mcap

### Example

```go
// listen on port 27017 for key payload
func main() {
	// ignore errors for now.
	ch := make(chan bsoncore.Value)
	go mcap.Listen(context.TODO(), "payload", 27017, ch)

	// start decoding payloads...
	payload := <-ch
}
```
