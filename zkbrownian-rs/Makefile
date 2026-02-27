IP ?= $(error IP is required, e.g. make launch-simulation IP=10.163.192.78)

# Which benchmark file to cross-compile and run (e.g. forward_bench, msm_bench)
BENCH ?= forward_bench
# Extra args passed to the benchmark binary (e.g. "-- forward$$" to filter)
BENCH_ARGS ?=

.PHONY: launch-simulation bench-android

bench-android:
	cargo bench --no-run --bench $(BENCH) --target aarch64-linux-android
	@BENCH_BIN=$$(ls -t target/aarch64-linux-android/release/deps/$(BENCH)-* 2>/dev/null | grep -v '\.d$$' | head -1) && \
	if [ -z "$$BENCH_BIN" ]; then echo "ERROR: No benchmark binary found for $(BENCH)"; exit 1; fi && \
	echo "Pushing $$BENCH_BIN to phone..." && \
	adb shell mkdir -p /data/local/tmp/zkbrownian && \
	adb push "$$BENCH_BIN" /data/local/tmp/zkbrownian/bench && \
	adb shell chmod +x /data/local/tmp/zkbrownian/bench && \
	echo "Running $(BENCH) on phone..." && \
	adb shell "cd /data/local/tmp/zkbrownian && ./bench $(BENCH_ARGS)"

launch-simulation:
	# Build phone binary for Android
	cargo build --release -p zkbrownian-simulator --bin phone --target aarch64-linux-android
	cargo build --release -p zkbrownian-simulator --bin server
	# Start tmux: left pane = server, right pane = phone (waits for server + push)
	tmux new-session -d -s zksim \
		'cd $(CURDIR) && cargo run --release -p zkbrownian-simulator --bin server -- \
            --num-nodes 5 --packets-per-node 128 --ttl 5; $$SHELL'
	tmux split-window -h -t zksim \
		'echo "Waiting for server to generate setup data..." && sleep 10 && \
		adb push $(CURDIR)/target/aarch64-linux-android/release/phone /data/local/tmp/zkbrownian/ && \
		adb push $(CURDIR)/setup-data/. /data/local/tmp/zkbrownian/ && \
		adb shell chmod +x /data/local/tmp/zkbrownian/phone && \
		adb shell /data/local/tmp/zkbrownian/phone \
			--server-url http://$(IP):8080 \
            --max-batch-size 32 \
			--setup-dir /data/local/tmp/zkbrownian; $$SHELL'
	tmux attach -t zksim
