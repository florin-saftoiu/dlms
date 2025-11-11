using Gurux.Common;
using Gurux.DLMS;
using Gurux.DLMS.Enums;
using Gurux.DLMS.Objects;
using Gurux.DLMS.Secure;
using Gurux.Net;
using listener;
using Microsoft.Extensions.Logging;
using System.Diagnostics;

Dictionary<string, string> encryptionKeys = new()
{
    // Only include the first 3 letters of the manufacturer !!! MFR0123456789012 becomes MFC123456789012 !!!
    { "MFR123456789012", "123456789ABCDEF0123456789ABCDEF0" }
};

static string UInt16FiveBitToString(byte[] value, int startIndex)
{
    UInt16 tmp = BitConverter.ToUInt16(value, startIndex); ;
    char c = (char)((tmp & 0x1f) + 0x40);
    tmp = (UInt16)(tmp >> 5);
    char c1 = (char)((tmp & 0x1f) + 0x40);
    tmp = (UInt16)(tmp >> 5);
    char c2 = (char)((tmp & 0x1f) + 0x40);
    return new([c2, c1, c]);
}
static uint BigEndianToUInt(byte[] value, int startIndex)
{
    // Extract 4 bytes starting at startIndex
    byte[] littleEndianValue = new byte[4];
    Array.Copy(value, startIndex, littleEndianValue, 0, 4);
    // Convert big-endian to little-endian
    Array.Reverse(littleEndianValue);
    // Convert to int
    return BitConverter.ToUInt32(littleEndianValue, 0);
}

using ILoggerFactory loggerFactory = LoggerFactory.Create(builder =>
{
    builder.AddSimpleConsole(options =>
    {
        options.SingleLine = true;
        options.TimestampFormat = "yyyy-MM-dd HH:mm:ss.fff ";
    });
    builder.SetMinimumLevel(LogLevel.Debug);
});
ILogger logger = loggerFactory.CreateLogger("listener");

var sessions = new Dictionary<string, Session>();

var pushSetup = new GXDLMSPushSetup();
pushSetup.PushObjectList.Add(new GXKeyValuePair<GXDLMSObject, GXDLMSCaptureObject>(new GXDLMSCompactData(), new GXDLMSCaptureObject(2, 0)));

var socket = new GXNet(NetworkType.Udp, 4059)
{
    Trace = TraceLevel.Verbose
};
socket.OnError += new Gurux.Common.ErrorEventHandler((object sender, Exception ex) =>
{
    logger.LogError(ex, "Error receiving communication from {sender}.", sender);
});
socket.OnReceived += new ReceivedEventHandler((object sender, ReceiveEventArgs e) =>
{
    logger.LogInformation("Incoming communication from {sender}.", e.SenderInfo);

    if (!sessions.TryGetValue(e.SenderInfo, out Session? session))
    {
        session = sessions[e.SenderInfo] = new Session()
        {
            Id = e.SenderInfo,
            Client = new GXDLMSSecureClient(true, 16, 1, Authentication.None, null, InterfaceType.WRAPPER)
            {
                ProposedConformance =
                Conformance.PriorityMgmtSupported |
                Conformance.Attribute0SupportedWithGet |
                Conformance.BlockTransferWithGetOrRead |
                Conformance.BlockTransferWithSetOrWrite |
                Conformance.BlockTransferWithAction |
                Conformance.MultipleReferences |
                Conformance.Get |
                Conformance.Set |
                Conformance.SelectiveAccess |
                Conformance.EventNotification |
                Conformance.Action
            }
        };
    }

    switch (session.State)
    {
        case Session.SessionState.New:
            if (e.Data is byte[] byteData)
            {
                string? manufacturer = null;
                string? serialNumber = null;
                object? eventData = null;
                try
                {
                    byte[] serialNumberValue = new byte[6];
                    Array.Copy(byteData, 12, serialNumberValue, 0, 6);
                    Array.Reverse(serialNumberValue);
                    serialNumber = BitConverter.ToString(serialNumberValue).Replace("-", "");
                    logger.LogInformation("Serial number {serialNumber}.", serialNumber);
                    manufacturer = UInt16FiveBitToString(byteData, 10);
                    logger.LogInformation("Manufacturer {manufacturer}.", manufacturer);
                }
                catch
                {
                    logger.LogInformation("Error parsing incoming communication {byteData}.", BitConverter.ToString(byteData).Replace("-", ""));
                }

                session.Client.Ciphering.AuthenticationKey = Convert.FromHexString(encryptionKeys[manufacturer + serialNumber]);
                session.Client.Ciphering.BlockCipherKey = Convert.FromHexString(encryptionKeys[manufacturer + serialNumber]);

                var reply = new GXByteBuffer();
                reply.Set(byteData);
                var data = new GXReplyData();
                var notify = new GXReplyData();
                session.Client.GetData(reply, data, notify);

                try
                {
                    logger.LogInformation("System title {byteData}.", BitConverter.ToString(notify.SystemTitle).Replace("-", " "));
                    session.Client.Ciphering.RecipientSystemTitle = notify.SystemTitle;
                    byte[] serialNumberValue = new byte[6];
                    Array.Copy(notify.SystemTitle, 2, serialNumberValue, 0, 6);
                    Array.Reverse(serialNumberValue);
                    serialNumber = BitConverter.ToString(serialNumberValue).Replace("-", "");

                    manufacturer = UInt16FiveBitToString(notify.SystemTitle, 0);

                    var clone = (GXDLMSPushSetup)pushSetup.Clone();
                    clone.GetPushValues(session.Client, (List<object>)notify.Value);
                    foreach (var pushObject in clone.PushObjectList)
                    {
                        int index = pushObject.Value.AttributeIndex - 1;
                        eventData = pushObject.Key.GetValues()[index];
                        if (eventData is byte[] eventBytes)
                        {
                            logger.LogInformation("Event data {byteData}.", BitConverter.ToString(eventBytes).Replace("-", " "));
                            session.ManagementFrameCounter = BigEndianToUInt(eventBytes, 117);
                            logger.LogInformation("Management frame counter {m}.", session.ManagementFrameCounter);
                        }
                    }
                }
                catch
                {
                    logger.LogInformation("Error parsing incoming communication {byteData}.", BitConverter.ToString(byteData).Replace("-", ""));
                }

                var aarq = session.Client.AARQRequest()[0];
                logger.LogInformation("AARQ {byteData}.", BitConverter.ToString(aarq).Replace("-", " "));
                socket.Send(aarq, e.SenderInfo);
                session.State = Session.SessionState.AARQ;
            }
            break;
        case Session.SessionState.AARQ:
            if (e.Data is byte[] aareByteData)
            {
                var reply = new GXByteBuffer();
                reply.Set(aareByteData);
                var data = new GXReplyData();
                session.Client.GetData(reply, data);
                session.Client.ParseAAREResponse(data.Data);
                logger.LogInformation("AARE data {byteData}.", data.Data.ToHex(true, 0));

                var publicFrameCounterRequest = session.Client.Read("0.0.43.1.1.255", ObjectType.Data, 2)[0];
                logger.LogInformation("Public frame counter request {byteData}.", BitConverter.ToString(publicFrameCounterRequest).Replace("-", " "));
                socket.Send(publicFrameCounterRequest, e.SenderInfo);
                session.State = Session.SessionState.PublicFrameCounterRequest;
            }
            break;
        case Session.SessionState.PublicFrameCounterRequest:
            if (e.Data is byte[] publicFrameCounterResponseByteData)
            {
                var reply = new GXByteBuffer();
                reply.Set(publicFrameCounterResponseByteData);
                var data = new GXReplyData();
                session.Client.GetData(reply, data);
                logger.LogInformation("Public frame counter response data {byteData}.", data.Data.ToHex(true, 0));

                var disconnectRequest = session.Client.DisconnectRequest();
                logger.LogInformation("Public disconnect request {byteData}.", BitConverter.ToString(disconnectRequest).Replace("-", " "));
                socket.Send(disconnectRequest, e.SenderInfo);
                session.State = Session.SessionState.DisconnectRequest;
            }
            break;
        case Session.SessionState.DisconnectRequest:
            if (e.Data is byte[] disconnectResponseByteData)
            {
                var reply = new GXByteBuffer();
                reply.Set(disconnectResponseByteData);
                var data = new GXReplyData();
                session.Client.GetData(reply, data);
                logger.LogInformation("Disconnect response data {byteData}.", data.Data.ToHex(true, 0));

                session.Client.Ciphering.Security = Security.AuthenticationEncryption;
                session.Client.Ciphering.InvocationCounter = session.ManagementFrameCounter + 1;
                session.Client.ClientAddress = 1;
                session.Client.Authentication = Authentication.Low;
                session.Client.Ciphering.SystemTitle = [ 0x53, 0x41, 0x43, 0x53, 0x41, 0x43, 0x53, 0x41 ];
                
                var clockRequest = session.Client.Read(new GXDLMSClock(), 2)[0];
                
                logger.LogInformation("Clock request {byteData}.", BitConverter.ToString(clockRequest).Replace("-", " "));
                socket.Send(clockRequest, e.SenderInfo);
                session.State = Session.SessionState.ClockRequest;
            }
            break;
        case Session.SessionState.ClockRequest:
            if (e.Data is byte[] clockResponseByteData)
            {
                var reply = new GXByteBuffer();
                reply.Set(clockResponseByteData);
                var data = new GXReplyData();
                session.Client.GetData(reply, data);
                logger.LogInformation("Clock response data {byteData}.", BitConverter.ToString(clockResponseByteData).Replace("-", " "));

                if (data.DataType == DataType.OctetString && data.Value is byte[] clockResponseValue)
                {
                    logger.LogInformation("Clock response value {value}.", BitConverter.ToString(clockResponseValue).Replace("-", " "));
                    GXByteBuffer buffer = new(clockResponseValue);
                    var obj = session.Client.ChangeType(buffer, DataType.DateTime);
                    if (obj is GXDateTime gxdt)
                    {
                        logger.LogInformation("Meter time {time}.", gxdt.Value.ToString());
                    }
                }

                var pushSetupRequest = session.Client.Read("0.1.25.9.0.255", ObjectType.PushSetup, 2)[0];

                logger.LogInformation("Push setup request {byteData}.", BitConverter.ToString(pushSetupRequest).Replace("-", " "));
                socket.Send(pushSetupRequest, e.SenderInfo);
                session.State = Session.SessionState.PushSetupRequest;
            }
            break;
        case Session.SessionState.PushSetupRequest:
            if (e.Data is byte[] pushSetupResponseByteData)
            {
                var reply = new GXByteBuffer();
                reply.Set(pushSetupResponseByteData);
                var data = new GXReplyData();
                session.Client.GetData(reply, data);
                logger.LogInformation("Push setup response data {byteData}.", BitConverter.ToString(pushSetupResponseByteData).Replace("-", " "));

                var getPushSchedulerRequest = session.Client.Read("0.1.15.0.4.255", ObjectType.ActionSchedule, 4)[0];

                logger.LogInformation("Get push scheduler request {byteData}.", BitConverter.ToString(getPushSchedulerRequest).Replace("-", " "));
                socket.Send(getPushSchedulerRequest, e.SenderInfo);
                session.State = Session.SessionState.GetPushSchedulerRequest;
            }
            break;
        case Session.SessionState.GetPushSchedulerRequest:
            if (e.Data is byte[] getPushSchedulerResponseByteData)
            {
                var reply = new GXByteBuffer();
                reply.Set(getPushSchedulerResponseByteData);
                var data = new GXReplyData();
                session.Client.GetData(reply, data);
                logger.LogInformation("Get push scheduler response data {byteData}.", BitConverter.ToString(getPushSchedulerResponseByteData).Replace("-", " "));

                byte[] activationTime = [9, 45, 0, 0];
                byte[] weekday = [0xFF, 0xFF, 0xFF, 0xFF, 0x02];
                GXStructure scheduleStruct = [activationTime, weekday];
                GXArray scheduleArray = [scheduleStruct];
                var setPushSchedulerRequest = session.Client.Write("0.1.15.0.4.255", scheduleArray, DataType.Array, ObjectType.ActionSchedule, 4)[0];

                logger.LogInformation("Set push scheduler request {byteData}.", BitConverter.ToString(setPushSchedulerRequest).Replace("-", " "));
                socket.Send(setPushSchedulerRequest, e.SenderInfo);
                session.State = Session.SessionState.SetPushSchedulerRequest;
            }
            break;
        case Session.SessionState.SetPushSchedulerRequest:
            if (e.Data is byte[] setPushSchedulerResponseByteData)
            {
                var reply = new GXByteBuffer();
                reply.Set(setPushSchedulerResponseByteData);
                var data = new GXReplyData();
                session.Client.GetData(reply, data);
                logger.LogInformation("Set push scheduler response data {byteData}.", BitConverter.ToString(setPushSchedulerResponseByteData).Replace("-", " "));

                sessions.Remove(e.SenderInfo);
            }
            break;
    }
});
socket.Open();

logger.LogInformation("Listening...");

while (true)
{
    if (Console.KeyAvailable)
    {
        var key = Console.ReadKey(intercept: true).Key;
        if (key == ConsoleKey.Escape)
        {
            logger.LogInformation("Shutting down...");

            socket.Dispose();

            break;
        }
    }
    // Small delay to prevent tight loop
    await System.Threading.Tasks.Task.Delay(50);
}
