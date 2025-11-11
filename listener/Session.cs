using Gurux.DLMS.Secure;

namespace listener
{
    public class Session
    {
        public enum SessionState
        {
            New,
            AARQ,
            PublicFrameCounterRequest,
            DisconnectRequest,
            ClockRequest,
            PushSetupRequest,
            GetPushSchedulerRequest,
            SetPushSchedulerRequest
        }
        public required string Id { get; set; }
        public required GXDLMSSecureClient Client { get; set; }
        public SessionState State { get; set; }
        public uint ManagementFrameCounter { get; set; }
    }
}
