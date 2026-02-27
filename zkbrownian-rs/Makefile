IP ?= $(error IP is required, e.g. make launch-simulation IP=10.163.192.78)

.PHONY: launch-simulation

launch-simulation:
	# Build phone binary for Android
	cargo build --release -p zkbrownian-simulator --bin phone --target aarch64-linux-android
	cargo build --release -p zkbrownian-simulator --bin server
	# Start tmux: left pane = server, right pane = phone (waits for server + push)
	tmux new-session -d -s zksim \
		'cd $(CURDIR) && cargo run --release -p zkbrownian-simulator --bin server -- \
			--server-verification --num-nodes 5 --packets-per-node 128 --ttl 5; $$SHELL'
	tmux split-window -h -t zksim \
		'echo "Waiting for server to generate setup data..." && sleep 10 && \
		adb push $(CURDIR)/target/aarch64-linux-android/release/phone /data/local/tmp/zkbrownian/ && \
		adb push $(CURDIR)/setup-data/. /data/local/tmp/zkbrownian/ && \
		adb shell chmod +x /data/local/tmp/zkbrownian/phone && \
		adb shell /data/local/tmp/zkbrownian/phone \
			--server-url http://$(IP):8080 \
            --server-verification \
            --max-batch-size 32 \
			--setup-dir /data/local/tmp/zkbrownian; $$SHELL'
	tmux attach -t zksim
