package main

var quit chan int = make(chan int)

func loop() {
	a := 1
	for i := 0; i < 10000; i++ {
		a = a + 1
	}

	quit <- 0
}
