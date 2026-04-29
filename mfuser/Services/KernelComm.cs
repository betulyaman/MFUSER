namespace mfuser.Services
{
    /// <summary>
    /// Abstraction over the kernel communication layer.
    /// </summary>
    public interface IKernelComm
    {
        /// <summary>Raised whenever the kernel sends a log line. May fire on a background thread.</summary>
        event EventHandler<string> LogReceived;

        /// <summary>Open the channel and start listening for kernel logs.</summary>
        void Start();

        /// <summary>Close the channel.</summary>
        void Stop();

        /// <summary>
        /// Send a (path, operation) pair down to the kernel.
        /// Returns true if the kernel acknowledged the request.
        /// </summary>
        bool SendOperation(string path, string operation);
    }

    /// <summary>
    /// Stub implementation. Replace the bodies with calls into your existing
    /// communication layer (DeviceIoControl, named pipe, FilterSendMessage, etc.).
    /// </summary>
    public class KernelComm : IKernelComm
    {
        public event EventHandler<string> LogReceived;

        private CancellationTokenSource _cts;
        private Task _readerTask;

        public void Start()
        {
            _cts = new CancellationTokenSource();
            _readerTask = Task.Run(() => ReadLoop(_cts.Token));
            LogReceived?.Invoke(this, "Kernel channel opened.");
        }

        public void Stop()
        {
            _cts?.Cancel();
            try { _readerTask?.Wait(500); } catch { /* ignore */ }
            LogReceived?.Invoke(this, "Kernel channel closed.");
        }

        public bool SendOperation(string path, string operation)
        {
            // TODO: Replace with your real call.
            // Example shapes you might already have:
            //
            //   _driver.SendIoctl(IOCTL_SHIELD, path);
            //   _filter.SendMessage(new ShieldRequest { Path = path, Op = operation });
            //   _pipe.WriteLine($"{operation}|{path}");
            //
            // Return whatever your layer says about success.
            LogReceived?.Invoke(this, $"-> kernel: {operation} {path}");
            return true;
        }

        // Demo loop - in your real code this is wherever you already read kernel messages.
        // If your comm layer already has its own thread / callback, just forward each
        // received line into LogReceived?.Invoke(this, line);
        private void ReadLoop(CancellationToken ct)
        {
            int i = 0;
            var rng = new Random();
            string[] samples =
            {
                "[kernel] heartbeat",
                "[kernel] shield applied to handle 0x{0:X4}",
                "[kernel] WARN: queue depth high ({0})",
                "[kernel] ERROR: failed to open device, code {0}",
                "[kernel] unshield completed in {0} ms"
            };

            while (!ct.IsCancellationRequested)
            {
                Thread.Sleep(1500);
                var template = samples[rng.Next(samples.Length)];
                LogReceived?.Invoke(this, string.Format(template, rng.Next(1, 9999)) + $" #{++i}");
            }
        }
    }
}
