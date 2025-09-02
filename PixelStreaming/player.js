//analizar de stats ---- jose
// let metricsLog = []
// let metricsHeaders = [  "timestamp",
//   "type",
//   "ssrc",
//   "packetsSent",
//   "bytesSent",
//   "packetsLost",
//   "bytesReceived",
//   "jitter",
//   "currentRoundTripTime",
//   "availableOutgoingBitrate",
//   "availableIncomingBitrate",]
const inboundVideoLog = [["timestamp","bytesReceived","packetsLost","jitter","jitterBufferDelay","jitterBufferEmittedCount","framesPerSecond","framesDropped"]];
const remoteOutboundVideoLog = [["timestamp","bytesSent","packetsSent"]];
const candidatePairLog = [["timestamp","bytesReceived","bytesSent","currentRoundTripTime","availableOutgoingBitrate","availableIncomingBitrate"]];
const inboundAudioLog = [["timestamp","bytesReceived","packetsLost","jitter","jitterBufferDelay","jitterBufferEmittedCount","concealedSamples"]];
const remoteInboundVideoLog = [["timestamp", "roundTripTime", "roundTripTimeMeasurements", "totalRoundTripTime", "currentRoundTripTime"]];
const latencyLog = [["timestamp", "networkLatencyMs", "encodeLatencyMs", "captureToSendMs", "endToEndLatencyMs", "captureToSendLatencyMs"]];
let prevSent = 0, prevRecv = 0;
//analizar de stats ---- jose

! function(e, t) {
    "object" == typeof exports && "object" == typeof module ? module.exports = t() : "function" == typeof define && define.amd ? define([], t) : "object" == typeof exports ? exports["epicgames-frontend"] = t() : e["epicgames-frontend"] = t()
}(this, (() => (() => {
    "use strict";
    var e = {
            107: (e, t, n) => {
                n.d(t, {
                    E: () => s
                });
                class s {
                    constructor(e, t, n, s, i = () => {}) {
                        this.parseURLParams(), this.onChange = i, this.onChangeEmit = () => {}, this.id = e, this.description = n, this.label = t, this.value = s
                    }
                    set label(e) {
                        this._label = e, this.onChangeEmit(this._value)
                    }
                    get label() {
                        return this._label
                    }
                    get value() {
                        return this._value
                    }
                    set value(e) {
                        this._value = e, this.onChange(this._value, this), this.onChangeEmit(this._value)
                    }
                    updateURLParams() {
                        if (this.useUrlParams) {
                            const e = new URLSearchParams(window.location.search),
                                t = this.getValueAsString();
                            let n = !1;
                            for (const [s, i] of e)
                                if (s.toLowerCase() == this.id.toLowerCase()) {
                                    e.set(s, t), n = !0;
                                    break
                                } n || e.set(this.id, t), window.history.replaceState({}, "", "" !== e.toString() ? `${location.pathname}?${e}` : `${location.pathname}`)
                        }
                    }
                    getValueAsString() {
                        return ""
                    }
                    parseURLParams() {
                        this._urlParams = {};
                        const e = new URLSearchParams(window.location.search);
                        for (const [t, n] of e) this._urlParams[t.toLowerCase()] = n
                    }
                    hasURLParam(e) {
                        return e.toLowerCase() in this._urlParams
                    }
                    getURLParam(e) {
                        return this.hasURLParam(e) ? this._urlParams[e.toLowerCase()] : ""
                    }
                }
            },
            171: (e, t, n) => {
                n.d(t, {
                    C: () => i
                });
                var s = n(879);
                class i {
                    static getSupportedVideoCodecs() {
                        const e = [];
                        if (!RTCRtpReceiver.getCapabilities) return s.Vy.Warning("RTCRtpReceiver.getCapabilities API is not available in your browser, defaulting to guess that we support H.264."), e.push("H264 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f"), e;
                        const t = /(VP\d|H26\d|AV1).*/,
                            n = RTCRtpReceiver.getCapabilities("video");
                        return n ? (n.codecs.forEach((n => {
                            const s = n.mimeType.split("/")[1] + " " + (n.sdpFmtpLine || "");
                            null !== t.exec(s) && e.push(s)
                        })), e) : (e.push("H264 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f"), e)
                    }
                }
            },
            202: (e, t, n) => {
                n.r(t), n.d(t, {
                    AfkLogic: () => Ke,
                    AfkTimedOutEvent: () => $e.Kr,
                    AfkWarningActivateEvent: () => $e.mC,
                    AfkWarningDeactivateEvent: () => $e.jr,
                    AfkWarningUpdateEvent: () => $e.S_,
                    AggregatedStats: () => st,
                    CandidatePairStats: () => tn,
                    CandidateStat: () => Ye,
                    Config: () => Qe.TS,
                    ControlSchemeType: () => Qe.Bs,
                    DataChannelCloseEvent: () => $e.CE,
                    DataChannelErrorEvent: () => $e.EQ,
                    DataChannelLatencyTestRecord: () => Yt,
                    DataChannelLatencyTestResponseEvent: () => $e.Fh,
                    DataChannelLatencyTestResultEvent: () => $e.L7,
                    DataChannelOpenEvent: () => $e.ys,
                    DataChannelStats: () => Je,
                    EncoderSettings: () => gt,
                    EventEmitter: () => c,
                    Flags: () => Qe.iI,
                    FrameTimingInfo: () => lt,
                    HideFreezeFrameEvent: () => $e.RW,
                    InboundAudioStats: () => qe,
                    InboundVideoStats: () => Xe,
                    InitialSettings: () => mt,
                    InitialSettingsEvent: () => $e.EG,
                    InputCoordTranslator: () => zt,
                    KeepaliveMonitor: () => We,
                    LatencyCalculatedEvent: () => $e.L0,
                    LatencyCalculator: () => ct,
                    LatencyInfo: () => dt,
                    LatencyTestResultEvent: () => $e.Cc,
                    LatencyTestResults: () => yt,
                    LoadFreezeFrameEvent: () => $e.vx,
                    LogLevel: () => a.$b,
                    Logger: () => a.Vy,
                    MessageDirection: () => Lt,
                    MessageHelpers: () => i,
                    MessageRegistry: () => Ne,
                    Messages: () => s,
                    NumericParameters: () => Qe.k$,
                    OptionParameters: () => Qe.mY,
                    OutboundRTPStats: () => Ze,
                    PixelStreaming: () => en,
                    PixelStreamingEventEmitter: () => $e.R5,
                    PixelStreamingSettings: () => pt,
                    PlayStreamErrorEvent: () => $e.vL,
                    PlayStreamEvent: () => $e.Lz,
                    PlayStreamRejectedEvent: () => $e.FJ,
                    PlayerCountEvent: () => $e.d2,
                    RemoteOutboundRTPStats: () => et,
                    SDPUtils: () => ot,
                    SettingBase: () => Kt.E,
                    SettingFlag: () => Gt.T,
                    SettingNumber: () => qt.U,
                    SettingOption: () => Xt.G,
                    SettingText: () => Jt.c,
                    SettingsChangedEvent: () => $e.Si,
                    ShowOnScreenKeyboardEvent: () => $e.Gi,
                    SignallingProtocol: () => h,
                    StatsReceivedEvent: () => $e.d_,
                    StreamLoadingEvent: () => $e.Bg,
                    StreamPreConnectEvent: () => $e.y6,
                    StreamPreDisconnectEvent: () => $e.iu,
                    StreamReconnectEvent: () => $e.oK,
                    StreamerIDChangedMessageEvent: () => $e.ie,
                    StreamerListMessageEvent: () => $e.jG,
                    SubscribeFailedEvent: () => $e._h,
                    TextParameters: () => Qe.gw,
                    VideoEncoderAvgQPEvent: () => $e.x1,
                    VideoInitializedEvent: () => $e.Qy,
                    WebRTCSettings: () => ft,
                    WebRtcAutoConnectEvent: () => $e.nV,
                    WebRtcConnectedEvent: () => $e.d4,
                    WebRtcConnectingEvent: () => $e.Ys,
                    WebRtcDisconnectedEvent: () => $e.Nu,
                    WebRtcFailedEvent: () => $e.tv,
                    WebRtcPlayerController: () => Qt,
                    WebRtcSdpAnswerEvent: () => $e.zx,
                    WebRtcSdpEvent: () => $e.xV,
                    WebRtcSdpOfferEvent: () => $e.PC,
                    WebRtcTCPRelayDetectedEvent: () => $e.KB,
                    WebSocketTransport: () => d,
                    WebSocketTransportNJS: () => rn,
                    WebXRController: () => $t.R,
                    XrFrameEvent: () => $e.qM,
                    XrSessionEndedEvent: () => $e.HH,
                    XrSessionStartedEvent: () => $e.ev,
                    isFlagId: () => Qe.CR,
                    isNumericId: () => Qe.tQ,
                    isOptionId: () => Qe.Ri,
                    isTextId: () => Qe.B9,
                    overrideLogger: () => a.hW
                });
                var s = {};
                n.r(s), n.d(s, {
                    answer: () => we,
                    base_message: () => ae,
                    config: () => ce,
                    dataChannelRequest: () => Ie,
                    disconnectPlayer: () => Me,
                    endpointId: () => he,
                    endpointIdConfirm: () => ue,
                    iceCandidate: () => Te,
                    iceCandidateData: () => Ee,
                    identify: () => de,
                    layerPreference: () => Pe,
                    listStreamers: () => pe,
                    offer: () => Ce,
                    peerConnectionOptions: () => le,
                    peerDataChannels: () => Le,
                    peerDataChannelsReady: () => Oe,
                    ping: () => xe,
                    playerConnected: () => be,
                    playerCount: () => _e,
                    playerDisconnected: () => Se,
                    pong: () => ke,
                    startStreaming: () => De,
                    stats: () => Ve,
                    stopStreaming: () => Ae,
                    streamerDataChannels: () => Fe,
                    streamerDisconnected: () => Re,
                    streamerIdChanged: () => me,
                    streamerList: () => ge,
                    subscribe: () => fe,
                    subscribeFailed: () => ve,
                    unsubscribe: () => ye
                });
                var i = {};
                n.r(i), n.d(i, {
                    createMessage: () => Ue,
                    validateMessage: () => Be
                });
                var r, o, a = n(879);
                class l {
                    constructor(e) {
                        this._args = [], this._callback = e
                    }
                    handleEvent(e) {
                        this._callback(...this._args), this._args = []
                    }
                    setArgs(...e) {
                        this._args = e
                    }
                }
                class c extends EventTarget {
                    constructor() {
                        super(), this._eventListeners = new Map
                    }
                    removeListenerInternal(e, t) {
                        if (this._eventListeners.has(e)) {
                            const n = this._eventListeners.get(e);
                            if (void 0 === n) return this;
                            for (let s = 0; s < n.length; ++s) {
                                const i = n[s];
                                if (i.callback === t) {
                                    super.removeEventListener(e, i.eventListenerWrapper), n.splice(s, 1);
                                    break
                                }
                            }
                        }
                        return this
                    }
                    addListener(e, t) {
                        return this.on(e, t)
                    }
                    on(e, t) {
                        var n;
                        const s = new l(t);
                        return super.addEventListener(e, s), this._eventListeners.has(e) || this._eventListeners.set(e, new Array), null === (n = this._eventListeners.get(e)) || void 0 === n || n.push({
                            callback: t,
                            eventListenerWrapper: s
                        }), this
                    }
                    once(e, t) {
                        var n;
                        const s = new l(((...n) => {
                            t(n), this.removeListenerInternal(e, t)
                        }));
                        return super.addEventListener(e, s, {
                            once: !0
                        }), this._eventListeners.has(e) || this._eventListeners.set(e, new Array), null === (n = this._eventListeners.get(e)) || void 0 === n || n.push({
                            callback: t,
                            eventListenerWrapper: s
                        }), this
                    }
                    removeListener(e, t) {
                        return this.removeListenerInternal(e, t), this
                    }
                    off(e, t) {
                        return this.removeListener(e, t)
                    }
                    removeAllListeners(e) {
                        if (this._eventListeners.has(e)) {
                            const t = this._eventListeners.get(e);
                            if (void 0 === t) return this;
                            for (const n of t) this.removeEventListener(e, n.eventListenerWrapper);
                            this._eventListeners.delete(e)
                        }
                        return this
                    }
                    emit(e, ...t) {
                        if (this._eventListeners.has(e)) {
                            const n = this._eventListeners.get(e);
                            if (void 0 === n) return !1;
                            for (const e of n) e.eventListenerWrapper.setArgs(...t);
                            return super.dispatchEvent(new Event(e)), !0
                        }
                        return !1
                    }
                }
                class d extends c {
                    constructor(e) {
                        super(), this.WS_OPEN_STATE = 1, this.protocols = e
                    }
                    sendMessage(e) {
                        this.webSocket && this.webSocket.send(e)
                    }
                    connect(e) {
                        a.Vy.Info(e);
                        try {
                            return this.webSocket = new WebSocket(e, this.protocols), this.webSocket.onopen = e => this.handleOnOpen(), this.webSocket.onerror = e => this.handleOnError(), this.webSocket.onclose = e => this.handleOnClose(e), this.webSocket.onmessage = e => this.handleOnMessage(e), this.webSocket.onmessagebinary = e => this.handleOnMessageBinary(e), !0
                        } catch (e) {
                            return a.Vy.Error(e), !1
                        }
                    }
                    disconnect(e, t) {
                        this.webSocket && this.webSocket.close(e, t)
                    }
                    isConnected() {
                        return !!this.webSocket && this.webSocket.readyState != WebSocket.CLOSED
                    }
                    handleOnMessageBinary(e) {
                        e && e.data && e.data.text().then((e => {
                            const t = new MessageEvent("messageFromBinary", {
                                data: e
                            });
                            this.handleOnMessage(t)
                        })).catch((e => {
                            a.Vy.Error(`Failed to parse binary blob from websocket, reason: ${e.message}`)
                        }))
                    }
                    handleOnMessage(e) {
                        e.data && e.data instanceof Blob ? this.handleOnMessageBinary(e) : this.onMessage && this.onMessage(e.data)
                    }
                    handleOnOpen() {
                        a.Vy.Info("Connected to the signalling server via WebSocket"), this.emit("open")
                    }
                    handleOnError() {
                        this.emit("error")
                    }
                    handleOnClose(e) {
                        a.Vy.Info("Disconnected to the signalling server via WebSocket: " + JSON.stringify(e.code) + " - " + e.reason), this.emit("close", e)
                    }
                }
                class h extends c {
                    static get SIGNALLING_VERSION() {
                        return "1.3.0"
                    }
                    constructor(e) {
                        super(), this.transport = e, e.onMessage = t => {
                            let n;
                            try {
                                const e = JSON.parse(t);
                                a.Vy.Debug("Protocol received => \n" + JSON.stringify(e, void 0, 4)), n = e
                            } catch (e) {
                                return void(e instanceof Error ? a.Vy.Error(`Error parsing message string ${t}.\n${e.message}`) : a.Vy.Error("Unknown error while parsing message data in handleOnMessage"))
                            }
                            e.emit("message", n), this.emit(n.type, n) || this.emit("unhandled", n)
                        }
                    }
                    connect(e) {
                        return this.transport.connect(e)
                    }
                    disconnect(e, t) {
                        this.transport.disconnect(e, t)
                    }
                    isConnected() {
                        return this.transport.isConnected()
                    }
                    sendMessage(e) {
                        this.transport.sendMessage(JSON.stringify(e)), this.transport.emit("out", e), a.Vy.Debug("Protocol sent => \n" + JSON.stringify(e, void 0, 4))
                    }
                }

                function u(e, t, n) {
                    let s, i, r = n;
                    for (let n of e.fields) {
                        let e = n.localName;
                        if (n.oneof) {
                            const o = r[n.oneof];
                            if (null == (null == o ? void 0 : o.oneofKind)) continue;
                            if (s = o[e], i = t[n.oneof], i.oneofKind = o.oneofKind, null == s) {
                                delete i[e];
                                continue
                            }
                        } else if (s = r[e], i = t, null == s) continue;
                        switch (n.repeat && (i[e].length = s.length), n.kind) {
                            case "scalar":
                            case "enum":
                                if (n.repeat)
                                    for (let t = 0; t < s.length; t++) i[e][t] = s[t];
                                else i[e] = s;
                                break;
                            case "message":
                                let t = n.T();
                                if (n.repeat)
                                    for (let n = 0; n < s.length; n++) i[e][n] = t.create(s[n]);
                                else void 0 === i[e] ? i[e] = t.create(s) : t.mergePartial(i[e], s);
                                break;
                            case "map":
                                switch (n.V.kind) {
                                    case "scalar":
                                    case "enum":
                                        Object.assign(i[e], s);
                                        break;
                                    case "message":
                                        let t = n.V.T();
                                        for (let n of Object.keys(s)) i[e][n] = t.create(s[n])
                                }
                        }
                    }
                }! function(e) {
                    e.symbol = Symbol.for("protobuf-ts/unknown"), e.onRead = (n, s, i, r, o) => {
                        (t(s) ? s[e.symbol] : s[e.symbol] = []).push({
                            no: i,
                            wireType: r,
                            data: o
                        })
                    }, e.onWrite = (t, n, s) => {
                        for (let {
                                no: t,
                                wireType: i,
                                data: r
                            }
                            of e.list(n)) s.tag(t, i).raw(r)
                    }, e.list = (n, s) => {
                        if (t(n)) {
                            let t = n[e.symbol];
                            return s ? t.filter((e => e.no == s)) : t
                        }
                        return []
                    }, e.last = (t, n) => e.list(t, n).slice(-1)[0];
                    const t = t => t && Array.isArray(t[e.symbol])
                }(r || (r = {})),
                function(e) {
                    e[e.Varint = 0] = "Varint", e[e.Bit64 = 1] = "Bit64", e[e.LengthDelimited = 2] = "LengthDelimited", e[e.StartGroup = 3] = "StartGroup", e[e.EndGroup = 4] = "EndGroup", e[e.Bit32 = 5] = "Bit32"
                }(o || (o = {}));
                const m = Symbol.for("protobuf-ts/message-type");

                function p(e) {
                    let t = !1;
                    const n = [];
                    for (let s = 0; s < e.length; s++) {
                        let i = e.charAt(s);
                        "_" == i ? t = !0 : /\d/.test(i) ? (n.push(i), t = !0) : t ? (n.push(i.toUpperCase()), t = !1) : 0 == s ? n.push(i.toLowerCase()) : n.push(i)
                    }
                    return n.join("")
                }
                var g, f, y;

                function v(e) {
                    var t, n, s, i;
                    return e.localName = null !== (t = e.localName) && void 0 !== t ? t : p(e.name), e.jsonName = null !== (n = e.jsonName) && void 0 !== n ? n : p(e.name), e.repeat = null !== (s = e.repeat) && void 0 !== s ? s : y.NO, e.opt = null !== (i = e.opt) && void 0 !== i ? i : !e.repeat && (!e.oneof && "message" == e.kind), e
                }

                function b(e) {
                    if ("object" != typeof e || null === e || !e.hasOwnProperty("oneofKind")) return !1;
                    switch (typeof e.oneofKind) {
                        case "string":
                            return void 0 !== e[e.oneofKind] && 2 == Object.keys(e).length;
                        case "undefined":
                            return 1 == Object.keys(e).length;
                        default:
                            return !1
                    }
                }! function(e) {
                    e[e.DOUBLE = 1] = "DOUBLE", e[e.FLOAT = 2] = "FLOAT", e[e.INT64 = 3] = "INT64", e[e.UINT64 = 4] = "UINT64", e[e.INT32 = 5] = "INT32", e[e.FIXED64 = 6] = "FIXED64", e[e.FIXED32 = 7] = "FIXED32", e[e.BOOL = 8] = "BOOL", e[e.STRING = 9] = "STRING", e[e.BYTES = 12] = "BYTES", e[e.UINT32 = 13] = "UINT32", e[e.SFIXED32 = 15] = "SFIXED32", e[e.SFIXED64 = 16] = "SFIXED64", e[e.SINT32 = 17] = "SINT32", e[e.SINT64 = 18] = "SINT64"
                }(g || (g = {})),
                function(e) {
                    e[e.BIGINT = 0] = "BIGINT", e[e.STRING = 1] = "STRING", e[e.NUMBER = 2] = "NUMBER"
                }(f || (f = {})),
                function(e) {
                    e[e.NO = 0] = "NO", e[e.PACKED = 1] = "PACKED", e[e.UNPACKED = 2] = "UNPACKED"
                }(y || (y = {}));
                class S {
                    constructor(e) {
                        var t;
                        this.fields = null !== (t = e.fields) && void 0 !== t ? t : []
                    }
                    prepare() {
                        if (this.data) return;
                        const e = [],
                            t = [],
                            n = [];
                        for (let s of this.fields)
                            if (s.oneof) n.includes(s.oneof) || (n.push(s.oneof), e.push(s.oneof), t.push(s.oneof));
                            else switch (t.push(s.localName), s.kind) {
                                case "scalar":
                                case "enum":
                                    s.opt && !s.repeat || e.push(s.localName);
                                    break;
                                case "message":
                                    s.repeat && e.push(s.localName);
                                    break;
                                case "map":
                                    e.push(s.localName)
                            }
                        this.data = {
                            req: e,
                            known: t,
                            oneofs: Object.values(n)
                        }
                    }
                    is(e, t, n = !1) {
                        if (t < 0) return !0;
                        if (null == e || "object" != typeof e) return !1;
                        this.prepare();
                        let s = Object.keys(e),
                            i = this.data;
                        if (s.length < i.req.length || i.req.some((e => !s.includes(e)))) return !1;
                        if (!n && s.some((e => !i.known.includes(e)))) return !1;
                        if (t < 1) return !0;
                        for (const s of i.oneofs) {
                            const i = e[s];
                            if (!b(i)) return !1;
                            if (void 0 === i.oneofKind) continue;
                            const r = this.fields.find((e => e.localName === i.oneofKind));
                            if (!r) return !1;
                            if (!this.field(i[i.oneofKind], r, n, t)) return !1
                        }
                        for (const s of this.fields)
                            if (void 0 === s.oneof && !this.field(e[s.localName], s, n, t)) return !1;
                        return !0
                    }
                    field(e, t, n, s) {
                        let i = t.repeat;
                        switch (t.kind) {
                            case "scalar":
                                return void 0 === e ? t.opt : i ? this.scalars(e, t.T, s, t.L) : this.scalar(e, t.T, t.L);
                            case "enum":
                                return void 0 === e ? t.opt : i ? this.scalars(e, g.INT32, s) : this.scalar(e, g.INT32);
                            case "message":
                                return void 0 === e || (i ? this.messages(e, t.T(), n, s) : this.message(e, t.T(), n, s));
                            case "map":
                                if ("object" != typeof e || null === e) return !1;
                                if (s < 2) return !0;
                                if (!this.mapKeys(e, t.K, s)) return !1;
                                switch (t.V.kind) {
                                    case "scalar":
                                        return this.scalars(Object.values(e), t.V.T, s, t.V.L);
                                    case "enum":
                                        return this.scalars(Object.values(e), g.INT32, s);
                                    case "message":
                                        return this.messages(Object.values(e), t.V.T(), n, s)
                                }
                        }
                        return !0
                    }
                    message(e, t, n, s) {
                        return n ? t.isAssignable(e, s) : t.is(e, s)
                    }
                    messages(e, t, n, s) {
                        if (!Array.isArray(e)) return !1;
                        if (s < 2) return !0;
                        if (n) {
                            for (let n = 0; n < e.length && n < s; n++)
                                if (!t.isAssignable(e[n], s - 1)) return !1
                        } else
                            for (let n = 0; n < e.length && n < s; n++)
                                if (!t.is(e[n], s - 1)) return !1;
                        return !0
                    }
                    scalar(e, t, n) {
                        let s = typeof e;
                        switch (t) {
                            case g.UINT64:
                            case g.FIXED64:
                            case g.INT64:
                            case g.SFIXED64:
                            case g.SINT64:
                                switch (n) {
                                    case f.BIGINT:
                                        return "bigint" == s;
                                    case f.NUMBER:
                                        return "number" == s && !isNaN(e);
                                    default:
                                        return "string" == s
                                }
                            case g.BOOL:
                                return "boolean" == s;
                            case g.STRING:
                                return "string" == s;
                            case g.BYTES:
                                return e instanceof Uint8Array;
                            case g.DOUBLE:
                            case g.FLOAT:
                                return "number" == s && !isNaN(e);
                            default:
                                return "number" == s && Number.isInteger(e)
                        }
                    }
                    scalars(e, t, n, s) {
                        if (!Array.isArray(e)) return !1;
                        if (n < 2) return !0;
                        if (Array.isArray(e))
                            for (let i = 0; i < e.length && i < n; i++)
                                if (!this.scalar(e[i], t, s)) return !1;
                        return !0
                    }
                    mapKeys(e, t, n) {
                        let s = Object.keys(e);
                        switch (t) {
                            case g.INT32:
                            case g.FIXED32:
                            case g.SFIXED32:
                            case g.SINT32:
                            case g.UINT32:
                                return this.scalars(s.slice(0, n).map((e => parseInt(e))), t, n);
                            case g.BOOL:
                                return this.scalars(s.slice(0, n).map((e => "true" == e || "false" != e && e)), t, n);
                            default:
                                return this.scalars(s, t, n, f.STRING)
                        }
                    }
                }

                function C(e) {
                    let t = typeof e;
                    if ("object" == t) {
                        if (Array.isArray(e)) return "array";
                        if (null === e) return "null"
                    }
                    return t
                }
                let w = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".split(""),
                    E = [];
                for (let e = 0; e < w.length; e++) E[w[e].charCodeAt(0)] = e;

                function T() {
                    let e = 0,
                        t = 0;
                    for (let n = 0; n < 28; n += 7) {
                        let s = this.buf[this.pos++];
                        if (e |= (127 & s) << n, !(128 & s)) return this.assertBounds(), [e, t]
                    }
                    let n = this.buf[this.pos++];
                    if (e |= (15 & n) << 28, t = (112 & n) >> 4, !(128 & n)) return this.assertBounds(), [e, t];
                    for (let n = 3; n <= 31; n += 7) {
                        let s = this.buf[this.pos++];
                        if (t |= (127 & s) << n, !(128 & s)) return this.assertBounds(), [e, t]
                    }
                    throw new Error("invalid varint")
                }

                function M(e, t, n) {
                    for (let s = 0; s < 28; s += 7) {
                        const i = e >>> s,
                            r = !(i >>> 7 == 0 && 0 == t),
                            o = 255 & (r ? 128 | i : i);
                        if (n.push(o), !r) return
                    }
                    const s = e >>> 28 & 15 | (7 & t) << 4,
                        i = !!(t >> 3);
                    if (n.push(255 & (i ? 128 | s : s)), i) {
                        for (let e = 3; e < 31; e += 7) {
                            const s = t >>> e,
                                i = !(s >>> 7 == 0),
                                r = 255 & (i ? 128 | s : s);
                            if (n.push(r), !i) return
                        }
                        n.push(t >>> 31 & 1)
                    }
                }
                E["-".charCodeAt(0)] = w.indexOf("+"), E["_".charCodeAt(0)] = w.indexOf("/");
                const x = 4294967296;

                function k(e) {
                    let t = "-" == e[0];
                    t && (e = e.slice(1));
                    const n = 1e6;
                    let s = 0,
                        i = 0;

                    function r(t, r) {
                        const o = Number(e.slice(t, r));
                        i *= n, s = s * n + o, s >= x && (i += s / x | 0, s %= x)
                    }
                    return r(-24, -18), r(-18, -12), r(-12, -6), r(-6), [t, s, i]
                }

                function R(e, t) {
                    if (t >>> 0 <= 2097151) return "" + (x * t + (e >>> 0));
                    let n = (e >>> 24 | t << 8) >>> 0 & 16777215,
                        s = t >> 16 & 65535,
                        i = (16777215 & e) + 6777216 * n + 6710656 * s,
                        r = n + 8147497 * s,
                        o = 2 * s,
                        a = 1e7;

                    function l(e, t) {
                        let n = e ? String(e) : "";
                        return t ? "0000000".slice(n.length) + n : n
                    }
                    return i >= a && (r += Math.floor(i / a), i %= a), r >= a && (o += Math.floor(r / a), r %= a), l(o, 0) + l(r, o) + l(i, 1)
                }

                function P(e, t) {
                    if (e >= 0) {
                        for (; e > 127;) t.push(127 & e | 128), e >>>= 7;
                        t.push(e)
                    } else {
                        for (let n = 0; n < 9; n++) t.push(127 & e | 128), e >>= 7;
                        t.push(1)
                    }
                }

                function I() {
                    let e = this.buf[this.pos++],
                        t = 127 & e;
                    if (!(128 & e)) return this.assertBounds(), t;
                    if (e = this.buf[this.pos++], t |= (127 & e) << 7, !(128 & e)) return this.assertBounds(), t;
                    if (e = this.buf[this.pos++], t |= (127 & e) << 14, !(128 & e)) return this.assertBounds(), t;
                    if (e = this.buf[this.pos++], t |= (127 & e) << 21, !(128 & e)) return this.assertBounds(), t;
                    e = this.buf[this.pos++], t |= (15 & e) << 28;
                    for (let t = 5; 128 & e && t < 10; t++) e = this.buf[this.pos++];
                    if (128 & e) throw new Error("invalid varint");
                    return this.assertBounds(), t >>> 0
                }
                let L;

                function O(e) {
                    if (!e) throw new Error("BigInt unavailable, see https://github.com/timostamm/protobuf-ts/blob/v1.0.8/MANUAL.md#bigint-support")
                }! function() {
                    const e = new DataView(new ArrayBuffer(8)),
                        t = void 0 !== globalThis.BigInt && "function" == typeof e.getBigInt64 && "function" == typeof e.getBigUint64 && "function" == typeof e.setBigInt64 && "function" == typeof e.setBigUint64;
                    L = t ? {
                        MIN: BigInt("-9223372036854775808"),
                        MAX: BigInt("9223372036854775807"),
                        UMIN: BigInt("0"),
                        UMAX: BigInt("18446744073709551615"),
                        C: BigInt,
                        V: e
                    } : void 0
                }();
                const F = /^-?[0-9]+$/,
                    D = 4294967296,
                    A = 2147483648;
                class _ {
                    constructor(e, t) {
                        this.lo = 0 | e, this.hi = 0 | t
                    }
                    isZero() {
                        return 0 == this.lo && 0 == this.hi
                    }
                    toNumber() {
                        let e = this.hi * D + (this.lo >>> 0);
                        if (!Number.isSafeInteger(e)) throw new Error("cannot convert to safe number");
                        return e
                    }
                }
                class V extends _ {
                    static from(e) {
                        if (L) switch (typeof e) {
                            case "string":
                                if ("0" == e) return this.ZERO;
                                if ("" == e) throw new Error("string is no integer");
                                e = L.C(e);
                            case "number":
                                if (0 === e) return this.ZERO;
                                e = L.C(e);
                            case "bigint":
                                if (!e) return this.ZERO;
                                if (e < L.UMIN) throw new Error("signed value for ulong");
                                if (e > L.UMAX) throw new Error("ulong too large");
                                return L.V.setBigUint64(0, e, !0), new V(L.V.getInt32(0, !0), L.V.getInt32(4, !0))
                        } else switch (typeof e) {
                            case "string":
                                if ("0" == e) return this.ZERO;
                                if (e = e.trim(), !F.test(e)) throw new Error("string is no integer");
                                let [t, n, s] = k(e);
                                if (t) throw new Error("signed value for ulong");
                                return new V(n, s);
                            case "number":
                                if (0 == e) return this.ZERO;
                                if (!Number.isSafeInteger(e)) throw new Error("number is no integer");
                                if (e < 0) throw new Error("signed value for ulong");
                                return new V(e, e / D)
                        }
                        throw new Error("unknown value " + typeof e)
                    }
                    toString() {
                        return L ? this.toBigInt().toString() : R(this.lo, this.hi)
                    }
                    toBigInt() {
                        return O(L), L.V.setInt32(0, this.lo, !0), L.V.setInt32(4, this.hi, !0), L.V.getBigUint64(0, !0)
                    }
                }
                V.ZERO = new V(0, 0);
                class N extends _ {
                    static from(e) {
                        if (L) switch (typeof e) {
                            case "string":
                                if ("0" == e) return this.ZERO;
                                if ("" == e) throw new Error("string is no integer");
                                e = L.C(e);
                            case "number":
                                if (0 === e) return this.ZERO;
                                e = L.C(e);
                            case "bigint":
                                if (!e) return this.ZERO;
                                if (e < L.MIN) throw new Error("signed long too small");
                                if (e > L.MAX) throw new Error("signed long too large");
                                return L.V.setBigInt64(0, e, !0), new N(L.V.getInt32(0, !0), L.V.getInt32(4, !0))
                        } else switch (typeof e) {
                            case "string":
                                if ("0" == e) return this.ZERO;
                                if (e = e.trim(), !F.test(e)) throw new Error("string is no integer");
                                let [t, n, s] = k(e);
                                if (t) {
                                    if (s > A || s == A && 0 != n) throw new Error("signed long too small")
                                } else if (s >= A) throw new Error("signed long too large");
                                let i = new N(n, s);
                                return t ? i.negate() : i;
                            case "number":
                                if (0 == e) return this.ZERO;
                                if (!Number.isSafeInteger(e)) throw new Error("number is no integer");
                                return e > 0 ? new N(e, e / D) : new N(-e, -e / D).negate()
                        }
                        throw new Error("unknown value " + typeof e)
                    }
                    isNegative() {
                        return !!(this.hi & A)
                    }
                    negate() {
                        let e = ~this.hi,
                            t = this.lo;
                        return t ? t = 1 + ~t : e += 1, new N(t, e)
                    }
                    toString() {
                        if (L) return this.toBigInt().toString();
                        if (this.isNegative()) {
                            let e = this.negate();
                            return "-" + R(e.lo, e.hi)
                        }
                        return R(this.lo, this.hi)
                    }
                    toBigInt() {
                        return O(L), L.V.setInt32(0, this.lo, !0), L.V.setInt32(4, this.hi, !0), L.V.getBigInt64(0, !0)
                    }
                }

                function U(e, t) {
                    if (!e) throw new Error(t)
                }
                N.ZERO = new N(0, 0);

                function B(e) {
                    if ("number" != typeof e) throw new Error("invalid int 32: " + typeof e);
                    if (!Number.isInteger(e) || e > 2147483647 || e < -2147483648) throw new Error("invalid int 32: " + e)
                }

                function W(e) {
                    if ("number" != typeof e) throw new Error("invalid uint 32: " + typeof e);
                    if (!Number.isInteger(e) || e > 4294967295 || e < 0) throw new Error("invalid uint 32: " + e)
                }

                function z(e) {
                    if ("number" != typeof e) throw new Error("invalid float 32: " + typeof e);
                    if (Number.isFinite(e) && (e > 34028234663852886e22 || e < -34028234663852886e22)) throw new Error("invalid float 32: " + e)
                }

                function H(e, t) {
                    switch (t) {
                        case f.BIGINT:
                            return e.toBigInt();
                        case f.NUMBER:
                            return e.toNumber();
                        default:
                            return e.toString()
                    }
                }
                class j {
                    constructor(e) {
                        this.info = e
                    }
                    prepare() {
                        var e;
                        if (void 0 === this.fMap) {
                            this.fMap = {};
                            const t = null !== (e = this.info.fields) && void 0 !== e ? e : [];
                            for (const e of t) this.fMap[e.name] = e, this.fMap[e.jsonName] = e, this.fMap[e.localName] = e
                        }
                    }
                    assert(e, t, n) {
                        if (!e) {
                            let e = C(n);
                            throw "number" != e && "boolean" != e || (e = n.toString()), new Error(`Cannot parse JSON ${e} for ${this.info.typeName}#${t}`)
                        }
                    }
                    read(e, t, n) {
                        this.prepare();
                        const s = [];
                        for (const [r, o] of Object.entries(e)) {
                            const e = this.fMap[r];
                            if (!e) {
                                if (!n.ignoreUnknownFields) throw new Error(`Found unknown field while reading ${this.info.typeName} from JSON format. JSON key: ${r}`);
                                continue
                            }
                            const a = e.localName;
                            let l;
                            if (e.oneof) {
                                if (null === o && ("enum" !== e.kind || "google.protobuf.NullValue" !== e.T()[0])) continue;
                                if (s.includes(e.oneof)) throw new Error(`Multiple members of the oneof group "${e.oneof}" of ${this.info.typeName} are present in JSON.`);
                                s.push(e.oneof), l = t[e.oneof] = {
                                    oneofKind: a
                                }
                            } else l = t;
                            if ("map" == e.kind) {
                                if (null === o) continue;
                                this.assert(null !== (i = o) && "object" == typeof i && !Array.isArray(i), e.name, o);
                                const t = l[a];
                                for (const [s, i] of Object.entries(o)) {
                                    let r;
                                    switch (this.assert(null !== i, e.name + " map value", null), e.V.kind) {
                                        case "message":
                                            r = e.V.T().internalJsonRead(i, n);
                                            break;
                                        case "enum":
                                            if (r = this.enum(e.V.T(), i, e.name, n.ignoreUnknownFields), !1 === r) continue;
                                            break;
                                        case "scalar":
                                            r = this.scalar(i, e.V.T, e.V.L, e.name)
                                    }
                                    this.assert(void 0 !== r, e.name + " map value", i);
                                    let o = s;
                                    e.K == g.BOOL && (o = "true" == o || "false" != o && o), o = this.scalar(o, e.K, f.STRING, e.name).toString(), t[o] = r
                                }
                            } else if (e.repeat) {
                                if (null === o) continue;
                                this.assert(Array.isArray(o), e.name, o);
                                const t = l[a];
                                for (const s of o) {
                                    let i;
                                    switch (this.assert(null !== s, e.name, null), e.kind) {
                                        case "message":
                                            i = e.T().internalJsonRead(s, n);
                                            break;
                                        case "enum":
                                            if (i = this.enum(e.T(), s, e.name, n.ignoreUnknownFields), !1 === i) continue;
                                            break;
                                        case "scalar":
                                            i = this.scalar(s, e.T, e.L, e.name)
                                    }
                                    this.assert(void 0 !== i, e.name, o), t.push(i)
                                }
                            } else switch (e.kind) {
                                case "message":
                                    if (null === o && "google.protobuf.Value" != e.T().typeName) {
                                        this.assert(void 0 === e.oneof, e.name + " (oneof member)", null);
                                        continue
                                    }
                                    l[a] = e.T().internalJsonRead(o, n, l[a]);
                                    break;
                                case "enum":
                                    if (null === o) continue;
                                    let t = this.enum(e.T(), o, e.name, n.ignoreUnknownFields);
                                    if (!1 === t) continue;
                                    l[a] = t;
                                    break;
                                case "scalar":
                                    if (null === o) continue;
                                    l[a] = this.scalar(o, e.T, e.L, e.name)
                            }
                        }
                        var i
                    }
                    enum(e, t, n, s) {
                        if ("google.protobuf.NullValue" == e[0] && U(null === t || "NULL_VALUE" === t, `Unable to parse field ${this.info.typeName}#${n}, enum ${e[0]} only accepts null.`), null === t) return 0;
                        switch (typeof t) {
                            case "number":
                                return U(Number.isInteger(t), `Unable to parse field ${this.info.typeName}#${n}, enum can only be integral number, got ${t}.`), t;
                            case "string":
                                let i = t;
                                e[2] && t.substring(0, e[2].length) === e[2] && (i = t.substring(e[2].length));
                                let r = e[1][i];
                                return (void 0 !== r || !s) && (U("number" == typeof r, `Unable to parse field ${this.info.typeName}#${n}, enum ${e[0]} has no value for "${t}".`), r)
                        }
                        U(!1, `Unable to parse field ${this.info.typeName}#${n}, cannot parse enum value from ${typeof t}".`)
                    }
                    scalar(e, t, n, s) {
                        let i;
                        try {
                            switch (t) {
                                case g.DOUBLE:
                                case g.FLOAT:
                                    if (null === e) return 0;
                                    if ("NaN" === e) return Number.NaN;
                                    if ("Infinity" === e) return Number.POSITIVE_INFINITY;
                                    if ("-Infinity" === e) return Number.NEGATIVE_INFINITY;
                                    if ("" === e) {
                                        i = "empty string";
                                        break
                                    }
                                    if ("string" == typeof e && e.trim().length !== e.length) {
                                        i = "extra whitespace";
                                        break
                                    }
                                    if ("string" != typeof e && "number" != typeof e) break;
                                    let s = Number(e);
                                    if (Number.isNaN(s)) {
                                        i = "not a number";
                                        break
                                    }
                                    if (!Number.isFinite(s)) {
                                        i = "too large or small";
                                        break
                                    }
                                    return t == g.FLOAT && z(s), s;
                                case g.INT32:
                                case g.FIXED32:
                                case g.SFIXED32:
                                case g.SINT32:
                                case g.UINT32:
                                    if (null === e) return 0;
                                    let r;
                                    if ("number" == typeof e ? r = e : "" === e ? i = "empty string" : "string" == typeof e && (e.trim().length !== e.length ? i = "extra whitespace" : r = Number(e)), void 0 === r) break;
                                    return t == g.UINT32 ? W(r) : B(r), r;
                                case g.INT64:
                                case g.SFIXED64:
                                case g.SINT64:
                                    if (null === e) return H(N.ZERO, n);
                                    if ("number" != typeof e && "string" != typeof e) break;
                                    return H(N.from(e), n);
                                case g.FIXED64:
                                case g.UINT64:
                                    if (null === e) return H(V.ZERO, n);
                                    if ("number" != typeof e && "string" != typeof e) break;
                                    return H(V.from(e), n);
                                case g.BOOL:
                                    if (null === e) return !1;
                                    if ("boolean" != typeof e) break;
                                    return e;
                                case g.STRING:
                                    if (null === e) return "";
                                    if ("string" != typeof e) {
                                        i = "extra whitespace";
                                        break
                                    }
                                    try {
                                        encodeURIComponent(e)
                                    } catch (i) {
                                        i = "invalid UTF8";
                                        break
                                    }
                                    return e;
                                case g.BYTES:
                                    if (null === e || "" === e) return new Uint8Array(0);
                                    if ("string" != typeof e) break;
                                    return function(e) {
                                        let t = 3 * e.length / 4;
                                        "=" == e[e.length - 2] ? t -= 2 : "=" == e[e.length - 1] && (t -= 1);
                                        let n, s = new Uint8Array(t),
                                            i = 0,
                                            r = 0,
                                            o = 0;
                                        for (let t = 0; t < e.length; t++) {
                                            if (n = E[e.charCodeAt(t)], void 0 === n) switch (e[t]) {
                                                case "=":
                                                    r = 0;
                                                case "\n":
                                                case "\r":
                                                case "\t":
                                                case " ":
                                                    continue;
                                                default:
                                                    throw Error("invalid base64 string.")
                                            }
                                            switch (r) {
                                                case 0:
                                                    o = n, r = 1;
                                                    break;
                                                case 1:
                                                    s[i++] = o << 2 | (48 & n) >> 4, o = n, r = 2;
                                                    break;
                                                case 2:
                                                    s[i++] = (15 & o) << 4 | (60 & n) >> 2, o = n, r = 3;
                                                    break;
                                                case 3:
                                                    s[i++] = (3 & o) << 6 | n, r = 0
                                            }
                                        }
                                        if (1 == r) throw Error("invalid base64 string.");
                                        return s.subarray(0, i)
                                    }(e)
                            }
                        } catch (e) {
                            i = e.message
                        }
                        this.assert(!1, s + (i ? " - " + i : ""), e)
                    }
                }
                class Q {
                    constructor(e) {
                        var t;
                        this.fields = null !== (t = e.fields) && void 0 !== t ? t : []
                    }
                    write(e, t) {
                        const n = {},
                            s = e;
                        for (const e of this.fields) {
                            if (!e.oneof) {
                                let i = this.field(e, s[e.localName], t);
                                void 0 !== i && (n[t.useProtoFieldName ? e.name : e.jsonName] = i);
                                continue
                            }
                            const i = s[e.oneof];
                            if (i.oneofKind !== e.localName) continue;
                            const r = "scalar" == e.kind || "enum" == e.kind ? Object.assign(Object.assign({}, t), {
                                emitDefaultValues: !0
                            }) : t;
                            let o = this.field(e, i[e.localName], r);
                            U(void 0 !== o), n[t.useProtoFieldName ? e.name : e.jsonName] = o
                        }
                        return n
                    }
                    field(e, t, n) {
                        let s;
                        if ("map" == e.kind) {
                            U("object" == typeof t && null !== t);
                            const i = {};
                            switch (e.V.kind) {
                                case "scalar":
                                    for (const [n, s] of Object.entries(t)) {
                                        const t = this.scalar(e.V.T, s, e.name, !1, !0);
                                        U(void 0 !== t), i[n.toString()] = t
                                    }
                                    break;
                                case "message":
                                    const s = e.V.T();
                                    for (const [r, o] of Object.entries(t)) {
                                        const t = this.message(s, o, e.name, n);
                                        U(void 0 !== t), i[r.toString()] = t
                                    }
                                    break;
                                case "enum":
                                    const r = e.V.T();
                                    for (const [s, o] of Object.entries(t)) {
                                        U(void 0 === o || "number" == typeof o);
                                        const t = this.enum(r, o, e.name, !1, !0, n.enumAsInteger);
                                        U(void 0 !== t), i[s.toString()] = t
                                    }
                            }(n.emitDefaultValues || Object.keys(i).length > 0) && (s = i)
                        } else if (e.repeat) {
                            U(Array.isArray(t));
                            const i = [];
                            switch (e.kind) {
                                case "scalar":
                                    for (let n = 0; n < t.length; n++) {
                                        const s = this.scalar(e.T, t[n], e.name, e.opt, !0);
                                        U(void 0 !== s), i.push(s)
                                    }
                                    break;
                                case "enum":
                                    const s = e.T();
                                    for (let r = 0; r < t.length; r++) {
                                        U(void 0 === t[r] || "number" == typeof t[r]);
                                        const o = this.enum(s, t[r], e.name, e.opt, !0, n.enumAsInteger);
                                        U(void 0 !== o), i.push(o)
                                    }
                                    break;
                                case "message":
                                    const r = e.T();
                                    for (let s = 0; s < t.length; s++) {
                                        const o = this.message(r, t[s], e.name, n);
                                        U(void 0 !== o), i.push(o)
                                    }
                            }(n.emitDefaultValues || i.length > 0 || n.emitDefaultValues) && (s = i)
                        } else switch (e.kind) {
                            case "scalar":
                                s = this.scalar(e.T, t, e.name, e.opt, n.emitDefaultValues);
                                break;
                            case "enum":
                                s = this.enum(e.T(), t, e.name, e.opt, n.emitDefaultValues, n.enumAsInteger);
                                break;
                            case "message":
                                s = this.message(e.T(), t, e.name, n)
                        }
                        return s
                    }
                    enum(e, t, n, s, i, r) {
                        if ("google.protobuf.NullValue" == e[0]) return i || s ? null : void 0;
                        if (void 0 !== t) {
                            if (0 !== t || i || s) return U("number" == typeof t), U(Number.isInteger(t)), r || !e[1].hasOwnProperty(t) ? t : e[2] ? e[2] + e[1][t] : e[1][t]
                        } else U(s)
                    }
                    message(e, t, n, s) {
                        return void 0 === t ? s.emitDefaultValues ? null : void 0 : e.internalJsonWrite(t, s)
                    }
                    scalar(e, t, n, s, i) {
                        if (void 0 === t) return void U(s);
                        const r = i || s;
                        switch (e) {
                            case g.INT32:
                            case g.SFIXED32:
                            case g.SINT32:
                                return 0 === t ? r ? 0 : void 0 : (B(t), t);
                            case g.FIXED32:
                            case g.UINT32:
                                return 0 === t ? r ? 0 : void 0 : (W(t), t);
                            case g.FLOAT:
                                z(t);
                            case g.DOUBLE:
                                return 0 === t ? r ? 0 : void 0 : (U("number" == typeof t), Number.isNaN(t) ? "NaN" : t === Number.POSITIVE_INFINITY ? "Infinity" : t === Number.NEGATIVE_INFINITY ? "-Infinity" : t);
                            case g.STRING:
                                return "" === t ? r ? "" : void 0 : (U("string" == typeof t), t);
                            case g.BOOL:
                                return !1 === t ? !r && void 0 : (U("boolean" == typeof t), t);
                            case g.UINT64:
                            case g.FIXED64:
                                U("number" == typeof t || "string" == typeof t || "bigint" == typeof t);
                                let e = V.from(t);
                                if (e.isZero() && !r) return;
                                return e.toString();
                            case g.INT64:
                            case g.SFIXED64:
                            case g.SINT64:
                                U("number" == typeof t || "string" == typeof t || "bigint" == typeof t);
                                let n = N.from(t);
                                if (n.isZero() && !r) return;
                                return n.toString();
                            case g.BYTES:
                                return U(t instanceof Uint8Array), t.byteLength ? function(e) {
                                    let t, n = "",
                                        s = 0,
                                        i = 0;
                                    for (let r = 0; r < e.length; r++) switch (t = e[r], s) {
                                        case 0:
                                            n += w[t >> 2], i = (3 & t) << 4, s = 1;
                                            break;
                                        case 1:
                                            n += w[i | t >> 4], i = (15 & t) << 2, s = 2;
                                            break;
                                        case 2:
                                            n += w[i | t >> 6], n += w[63 & t], s = 0
                                    }
                                    return s && (n += w[i], n += "=", 1 == s && (n += "=")), n
                                }(t) : r ? "" : void 0
                        }
                    }
                }

                function $(e, t = f.STRING) {
                    switch (e) {
                        case g.BOOL:
                            return !1;
                        case g.UINT64:
                        case g.FIXED64:
                            return H(V.ZERO, t);
                        case g.INT64:
                        case g.SFIXED64:
                        case g.SINT64:
                            return H(N.ZERO, t);
                        case g.DOUBLE:
                        case g.FLOAT:
                            return 0;
                        case g.BYTES:
                            return new Uint8Array(0);
                        case g.STRING:
                            return "";
                        default:
                            return 0
                    }
                }
                class K {
                    constructor(e) {
                        this.info = e
                    }
                    prepare() {
                        var e;
                        if (!this.fieldNoToField) {
                            const t = null !== (e = this.info.fields) && void 0 !== e ? e : [];
                            this.fieldNoToField = new Map(t.map((e => [e.no, e])))
                        }
                    }
                    read(e, t, n, s) {
                        this.prepare();
                        const i = void 0 === s ? e.len : e.pos + s;
                        for (; e.pos < i;) {
                            const [s, i] = e.tag(), a = this.fieldNoToField.get(s);
                            if (!a) {
                                let o = n.readUnknownField;
                                if ("throw" == o) throw new Error(`Unknown field ${s} (wire type ${i}) for ${this.info.typeName}`);
                                let a = e.skip(i);
                                !1 !== o && (!0 === o ? r.onRead : o)(this.info.typeName, t, s, i, a);
                                continue
                            }
                            let l = t,
                                c = a.repeat,
                                d = a.localName;
                            switch (a.oneof && (l = l[a.oneof], l.oneofKind !== d && (l = t[a.oneof] = {
                                    oneofKind: d
                                })), a.kind) {
                                case "scalar":
                                case "enum":
                                    let t = "enum" == a.kind ? g.INT32 : a.T,
                                        s = "scalar" == a.kind ? a.L : void 0;
                                    if (c) {
                                        let n = l[d];
                                        if (i == o.LengthDelimited && t != g.STRING && t != g.BYTES) {
                                            let i = e.uint32() + e.pos;
                                            for (; e.pos < i;) n.push(this.scalar(e, t, s))
                                        } else n.push(this.scalar(e, t, s))
                                    } else l[d] = this.scalar(e, t, s);
                                    break;
                                case "message":
                                    if (c) {
                                        let t = l[d],
                                            s = a.T().internalBinaryRead(e, e.uint32(), n);
                                        t.push(s)
                                    } else l[d] = a.T().internalBinaryRead(e, e.uint32(), n, l[d]);
                                    break;
                                case "map":
                                    let [r, h] = this.mapEntry(a, e, n);
                                    l[d][r] = h
                            }
                        }
                    }
                    mapEntry(e, t, n) {
                        let s, i, r = t.uint32(),
                            o = t.pos + r;
                        for (; t.pos < o;) {
                            let [r, o] = t.tag();
                            switch (r) {
                                case 1:
                                    s = e.K == g.BOOL ? t.bool().toString() : this.scalar(t, e.K, f.STRING);
                                    break;
                                case 2:
                                    switch (e.V.kind) {
                                        case "scalar":
                                            i = this.scalar(t, e.V.T, e.V.L);
                                            break;
                                        case "enum":
                                            i = t.int32();
                                            break;
                                        case "message":
                                            i = e.V.T().internalBinaryRead(t, t.uint32(), n)
                                    }
                                    break;
                                default:
                                    throw new Error(`Unknown field ${r} (wire type ${o}) in map entry for ${this.info.typeName}#${e.name}`)
                            }
                        }
                        if (void 0 === s) {
                            let t = $(e.K);
                            s = e.K == g.BOOL ? t.toString() : t
                        }
                        if (void 0 === i) switch (e.V.kind) {
                            case "scalar":
                                i = $(e.V.T, e.V.L);
                                break;
                            case "enum":
                                i = 0;
                                break;
                            case "message":
                                i = e.V.T().create()
                        }
                        return [s, i]
                    }
                    scalar(e, t, n) {
                        switch (t) {
                            case g.INT32:
                                return e.int32();
                            case g.STRING:
                                return e.string();
                            case g.BOOL:
                                return e.bool();
                            case g.DOUBLE:
                                return e.double();
                            case g.FLOAT:
                                return e.float();
                            case g.INT64:
                                return H(e.int64(), n);
                            case g.UINT64:
                                return H(e.uint64(), n);
                            case g.FIXED64:
                                return H(e.fixed64(), n);
                            case g.FIXED32:
                                return e.fixed32();
                            case g.BYTES:
                                return e.bytes();
                            case g.UINT32:
                                return e.uint32();
                            case g.SFIXED32:
                                return e.sfixed32();
                            case g.SFIXED64:
                                return H(e.sfixed64(), n);
                            case g.SINT32:
                                return e.sint32();
                            case g.SINT64:
                                return H(e.sint64(), n)
                        }
                    }
                }
                class G {
                    constructor(e) {
                        this.info = e
                    }
                    prepare() {
                        if (!this.fields) {
                            const e = this.info.fields ? this.info.fields.concat() : [];
                            this.fields = e.sort(((e, t) => e.no - t.no))
                        }
                    }
                    write(e, t, n) {
                        this.prepare();
                        for (const s of this.fields) {
                            let i, r, o = s.repeat,
                                a = s.localName;
                            if (s.oneof) {
                                const t = e[s.oneof];
                                if (t.oneofKind !== a) continue;
                                i = t[a], r = !0
                            } else i = e[a], r = !1;
                            switch (s.kind) {
                                case "scalar":
                                case "enum":
                                    let e = "enum" == s.kind ? g.INT32 : s.T;
                                    if (o)
                                        if (U(Array.isArray(i)), o == y.PACKED) this.packed(t, e, s.no, i);
                                        else
                                            for (const n of i) this.scalar(t, e, s.no, n, !0);
                                    else void 0 === i ? U(s.opt) : this.scalar(t, e, s.no, i, r || s.opt);
                                    break;
                                case "message":
                                    if (o) {
                                        U(Array.isArray(i));
                                        for (const e of i) this.message(t, n, s.T(), s.no, e)
                                    } else this.message(t, n, s.T(), s.no, i);
                                    break;
                                case "map":
                                    U("object" == typeof i && null !== i);
                                    for (const [e, r] of Object.entries(i)) this.mapEntry(t, n, s, e, r)
                            }
                        }
                        let s = n.writeUnknownFields;
                        !1 !== s && (!0 === s ? r.onWrite : s)(this.info.typeName, e, t)
                    }
                    mapEntry(e, t, n, s, i) {
                        e.tag(n.no, o.LengthDelimited), e.fork();
                        let r = s;
                        switch (n.K) {
                            case g.INT32:
                            case g.FIXED32:
                            case g.UINT32:
                            case g.SFIXED32:
                            case g.SINT32:
                                r = Number.parseInt(s);
                                break;
                            case g.BOOL:
                                U("true" == s || "false" == s), r = "true" == s
                        }
                        switch (this.scalar(e, n.K, 1, r, !0), n.V.kind) {
                            case "scalar":
                                this.scalar(e, n.V.T, 2, i, !0);
                                break;
                            case "enum":
                                this.scalar(e, g.INT32, 2, i, !0);
                                break;
                            case "message":
                                this.message(e, t, n.V.T(), 2, i)
                        }
                        e.join()
                    }
                    message(e, t, n, s, i) {
                        void 0 !== i && (n.internalBinaryWrite(i, e.tag(s, o.LengthDelimited).fork(), t), e.join())
                    }
                    scalar(e, t, n, s, i) {
                        let [r, o, a] = this.scalarInfo(t, s);
                        a && !i || (e.tag(n, r), e[o](s))
                    }
                    packed(e, t, n, s) {
                        if (!s.length) return;
                        U(t !== g.BYTES && t !== g.STRING), e.tag(n, o.LengthDelimited), e.fork();
                        let [, i] = this.scalarInfo(t);
                        for (let t = 0; t < s.length; t++) e[i](s[t]);
                        e.join()
                    }
                    scalarInfo(e, t) {
                        let n, s = o.Varint,
                            i = void 0 === t,
                            r = 0 === t;
                        switch (e) {
                            case g.INT32:
                                n = "int32";
                                break;
                            case g.STRING:
                                r = i || !t.length, s = o.LengthDelimited, n = "string";
                                break;
                            case g.BOOL:
                                r = !1 === t, n = "bool";
                                break;
                            case g.UINT32:
                                n = "uint32";
                                break;
                            case g.DOUBLE:
                                s = o.Bit64, n = "double";
                                break;
                            case g.FLOAT:
                                s = o.Bit32, n = "float";
                                break;
                            case g.INT64:
                                r = i || N.from(t).isZero(), n = "int64";
                                break;
                            case g.UINT64:
                                r = i || V.from(t).isZero(), n = "uint64";
                                break;
                            case g.FIXED64:
                                r = i || V.from(t).isZero(), s = o.Bit64, n = "fixed64";
                                break;
                            case g.BYTES:
                                r = i || !t.byteLength, s = o.LengthDelimited, n = "bytes";
                                break;
                            case g.FIXED32:
                                s = o.Bit32, n = "fixed32";
                                break;
                            case g.SFIXED32:
                                s = o.Bit32, n = "sfixed32";
                                break;
                            case g.SFIXED64:
                                r = i || N.from(t).isZero(), s = o.Bit64, n = "sfixed64";
                                break;
                            case g.SINT32:
                                n = "sint32";
                                break;
                            case g.SINT64:
                                r = i || N.from(t).isZero(), n = "sint64"
                        }
                        return [s, n, i || r]
                    }
                }
                const q = {
                        emitDefaultValues: !1,
                        enumAsInteger: !1,
                        useProtoFieldName: !1,
                        prettySpaces: 0
                    },
                    X = {
                        ignoreUnknownFields: !1
                    };
                const J = Object.values;

                function Y(e, t, n) {
                    if (t === n) return !0;
                    if (e !== g.BYTES) return !1;
                    let s = t,
                        i = n;
                    if (s.length !== i.length) return !1;
                    for (let e = 0; e < s.length; e++)
                        if (s[e] != i[e]) return !1;
                    return !0
                }

                function Z(e, t, n) {
                    if (t.length !== n.length) return !1;
                    for (let s = 0; s < t.length; s++)
                        if (!Y(e, t[s], n[s])) return !1;
                    return !0
                }

                function ee(e, t, n) {
                    if (t.length !== n.length) return !1;
                    for (let s = 0; s < t.length; s++)
                        if (!e.equals(t[s], n[s])) return !1;
                    return !0
                }
                const te = {
                    writeUnknownFields: !0,
                    writerFactory: () => new ne
                };
                class ne {
                    constructor(e) {
                        this.stack = [], this.textEncoder = null != e ? e : new TextEncoder, this.chunks = [], this.buf = []
                    }
                    finish() {
                        this.chunks.push(new Uint8Array(this.buf));
                        let e = 0;
                        for (let t = 0; t < this.chunks.length; t++) e += this.chunks[t].length;
                        let t = new Uint8Array(e),
                            n = 0;
                        for (let e = 0; e < this.chunks.length; e++) t.set(this.chunks[e], n), n += this.chunks[e].length;
                        return this.chunks = [], t
                    }
                    fork() {
                        return this.stack.push({
                            chunks: this.chunks,
                            buf: this.buf
                        }), this.chunks = [], this.buf = [], this
                    }
                    join() {
                        let e = this.finish(),
                            t = this.stack.pop();
                        if (!t) throw new Error("invalid state, fork stack empty");
                        return this.chunks = t.chunks, this.buf = t.buf, this.uint32(e.byteLength), this.raw(e)
                    }
                    tag(e, t) {
                        return this.uint32((e << 3 | t) >>> 0)
                    }
                    raw(e) {
                        return this.buf.length && (this.chunks.push(new Uint8Array(this.buf)), this.buf = []), this.chunks.push(e), this
                    }
                    uint32(e) {
                        for (W(e); e > 127;) this.buf.push(127 & e | 128), e >>>= 7;
                        return this.buf.push(e), this
                    }
                    int32(e) {
                        return B(e), P(e, this.buf), this
                    }
                    bool(e) {
                        return this.buf.push(e ? 1 : 0), this
                    }
                    bytes(e) {
                        return this.uint32(e.byteLength), this.raw(e)
                    }
                    string(e) {
                        let t = this.textEncoder.encode(e);
                        return this.uint32(t.byteLength), this.raw(t)
                    }
                    float(e) {
                        z(e);
                        let t = new Uint8Array(4);
                        return new DataView(t.buffer).setFloat32(0, e, !0), this.raw(t)
                    }
                    double(e) {
                        let t = new Uint8Array(8);
                        return new DataView(t.buffer).setFloat64(0, e, !0), this.raw(t)
                    }
                    fixed32(e) {
                        W(e);
                        let t = new Uint8Array(4);
                        return new DataView(t.buffer).setUint32(0, e, !0), this.raw(t)
                    }
                    sfixed32(e) {
                        B(e);
                        let t = new Uint8Array(4);
                        return new DataView(t.buffer).setInt32(0, e, !0), this.raw(t)
                    }
                    sint32(e) {
                        return B(e), P(e = (e << 1 ^ e >> 31) >>> 0, this.buf), this
                    }
                    sfixed64(e) {
                        let t = new Uint8Array(8),
                            n = new DataView(t.buffer),
                            s = N.from(e);
                        return n.setInt32(0, s.lo, !0), n.setInt32(4, s.hi, !0), this.raw(t)
                    }
                    fixed64(e) {
                        let t = new Uint8Array(8),
                            n = new DataView(t.buffer),
                            s = V.from(e);
                        return n.setInt32(0, s.lo, !0), n.setInt32(4, s.hi, !0), this.raw(t)
                    }
                    int64(e) {
                        let t = N.from(e);
                        return M(t.lo, t.hi, this.buf), this
                    }
                    sint64(e) {
                        let t = N.from(e),
                            n = t.hi >> 31;
                        return M(t.lo << 1 ^ n, (t.hi << 1 | t.lo >>> 31) ^ n, this.buf), this
                    }
                    uint64(e) {
                        let t = V.from(e);
                        return M(t.lo, t.hi, this.buf), this
                    }
                }
                const se = {
                    readUnknownField: !0,
                    readerFactory: e => new ie(e)
                };
                class ie {
                    constructor(e, t) {
                        this.varint64 = T, this.uint32 = I, this.buf = e, this.len = e.length, this.pos = 0, this.view = new DataView(e.buffer, e.byteOffset, e.byteLength), this.textDecoder = null != t ? t : new TextDecoder("utf-8", {
                            fatal: !0,
                            ignoreBOM: !0
                        })
                    }
                    tag() {
                        let e = this.uint32(),
                            t = e >>> 3,
                            n = 7 & e;
                        if (t <= 0 || n < 0 || n > 5) throw new Error("illegal tag: field no " + t + " wire type " + n);
                        return [t, n]
                    }
                    skip(e) {
                        let t = this.pos;
                        switch (e) {
                            case o.Varint:
                                for (; 128 & this.buf[this.pos++];);
                                break;
                            case o.Bit64:
                                this.pos += 4;
                            case o.Bit32:
                                this.pos += 4;
                                break;
                            case o.LengthDelimited:
                                let t = this.uint32();
                                this.pos += t;
                                break;
                            case o.StartGroup:
                                let n;
                                for (;
                                    (n = this.tag()[1]) !== o.EndGroup;) this.skip(n);
                                break;
                            default:
                                throw new Error("cant skip wire type " + e)
                        }
                        return this.assertBounds(), this.buf.subarray(t, this.pos)
                    }
                    assertBounds() {
                        if (this.pos > this.len) throw new RangeError("premature EOF")
                    }
                    int32() {
                        return 0 | this.uint32()
                    }
                    sint32() {
                        let e = this.uint32();
                        return e >>> 1 ^ -(1 & e)
                    }
                    int64() {
                        return new N(...this.varint64())
                    }
                    uint64() {
                        return new V(...this.varint64())
                    }
                    sint64() {
                        let [e, t] = this.varint64(), n = -(1 & e);
                        return e = (e >>> 1 | (1 & t) << 31) ^ n, t = t >>> 1 ^ n, new N(e, t)
                    }
                    bool() {
                        let [e, t] = this.varint64();
                        return 0 !== e || 0 !== t
                    }
                    fixed32() {
                        return this.view.getUint32((this.pos += 4) - 4, !0)
                    }
                    sfixed32() {
                        return this.view.getInt32((this.pos += 4) - 4, !0)
                    }
                    fixed64() {
                        return new V(this.sfixed32(), this.sfixed32())
                    }
                    sfixed64() {
                        return new N(this.sfixed32(), this.sfixed32())
                    }
                    float() {
                        return this.view.getFloat32((this.pos += 4) - 4, !0)
                    }
                    double() {
                        return this.view.getFloat64((this.pos += 8) - 8, !0)
                    }
                    bytes() {
                        let e = this.uint32(),
                            t = this.pos;
                        return this.pos += e, this.assertBounds(), this.buf.subarray(t, t + e)
                    }
                    string() {
                        return this.textDecoder.decode(this.bytes())
                    }
                }
                const re = Object.getOwnPropertyDescriptors(Object.getPrototypeOf({}));
                class oe {
                    constructor(e, t, n) {
                        this.defaultCheckDepth = 16, this.typeName = e, this.fields = t.map(v), this.options = null != n ? n : {}, this.messagePrototype = Object.create(null, Object.assign(Object.assign({}, re), {
                            [m]: {
                                value: this
                            }
                        })), this.refTypeCheck = new S(this), this.refJsonReader = new j(this), this.refJsonWriter = new Q(this), this.refBinReader = new K(this), this.refBinWriter = new G(this)
                    }
                    create(e) {
                        let t = function(e) {
                            const t = e.messagePrototype ? Object.create(e.messagePrototype) : Object.defineProperty({}, m, {
                                value: e
                            });
                            for (let n of e.fields) {
                                let e = n.localName;
                                if (!n.opt)
                                    if (n.oneof) t[n.oneof] = {
                                        oneofKind: void 0
                                    };
                                    else if (n.repeat) t[e] = [];
                                else switch (n.kind) {
                                    case "scalar":
                                        t[e] = $(n.T, n.L);
                                        break;
                                    case "enum":
                                        t[e] = 0;
                                        break;
                                    case "map":
                                        t[e] = {}
                                }
                            }
                            return t
                        }(this);
                        return void 0 !== e && u(this, t, e), t
                    }
                    clone(e) {
                        let t = this.create();
                        return u(this, t, e), t
                    }
                    equals(e, t) {
                        return function(e, t, n) {
                            if (t === n) return !0;
                            if (!t || !n) return !1;
                            for (let s of e.fields) {
                                let e = s.localName,
                                    i = s.oneof ? t[s.oneof][e] : t[e],
                                    r = s.oneof ? n[s.oneof][e] : n[e];
                                switch (s.kind) {
                                    case "enum":
                                    case "scalar":
                                        let e = "enum" == s.kind ? g.INT32 : s.T;
                                        if (!(s.repeat ? Z(e, i, r) : Y(e, i, r))) return !1;
                                        break;
                                    case "map":
                                        if (!("message" == s.V.kind ? ee(s.V.T(), J(i), J(r)) : Z("enum" == s.V.kind ? g.INT32 : s.V.T, J(i), J(r)))) return !1;
                                        break;
                                    case "message":
                                        let t = s.T();
                                        if (!(s.repeat ? ee(t, i, r) : t.equals(i, r))) return !1
                                }
                            }
                            return !0
                        }(this, e, t)
                    }
                    is(e, t = this.defaultCheckDepth) {
                        return this.refTypeCheck.is(e, t, !1)
                    }
                    isAssignable(e, t = this.defaultCheckDepth) {
                        return this.refTypeCheck.is(e, t, !0)
                    }
                    mergePartial(e, t) {
                        u(this, e, t)
                    }
                    fromBinary(e, t) {
                        let n = function(e) {
                            return e ? Object.assign(Object.assign({}, se), e) : se
                        }(t);
                        return this.internalBinaryRead(n.readerFactory(e), e.byteLength, n)
                    }
                    fromJson(e, t) {
                        return this.internalJsonRead(e, function(e) {
                            return e ? Object.assign(Object.assign({}, X), e) : X
                        }(t))
                    }
                    fromJsonString(e, t) {
                        let n = JSON.parse(e);
                        return this.fromJson(n, t)
                    }
                    toJson(e, t) {
                        return this.internalJsonWrite(e, function(e) {
                            return e ? Object.assign(Object.assign({}, q), e) : q
                        }(t))
                    }
                    toJsonString(e, t) {
                        var n;
                        let s = this.toJson(e, t);
                        return JSON.stringify(s, null, null !== (n = null == t ? void 0 : t.prettySpaces) && void 0 !== n ? n : 0)
                    }
                    toBinary(e, t) {
                        let n = function(e) {
                            return e ? Object.assign(Object.assign({}, te), e) : te
                        }(t);
                        return this.internalBinaryWrite(e, n.writerFactory(), n).finish()
                    }
                    internalJsonRead(e, t, n) {
                        if (null !== e && "object" == typeof e && !Array.isArray(e)) {
                            let s = null != n ? n : this.create();
                            return this.refJsonReader.read(e, s, t), s
                        }
                        throw new Error(`Unable to parse message ${this.typeName} from JSON ${C(e)}.`)
                    }
                    internalJsonWrite(e, t) {
                        return this.refJsonWriter.write(e, t)
                    }
                    internalBinaryWrite(e, t, n) {
                        return this.refBinWriter.write(e, t, n), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create();
                        return this.refBinReader.read(e, i, n, t), i
                    }
                }
                const ae = new class extends oe {
                    constructor() {
                        super("base_message", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            if (1 === t) i.type = e.string();
                            else {
                                let o = n.readUnknownField;
                                if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                let a = e.skip(s);
                                !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const le = new class extends oe {
                    constructor() {
                        super("peerConnectionOptions", [])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            {
                                let o = n.readUnknownField;
                                if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                let a = e.skip(s);
                                !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const ce = new class extends oe {
                    constructor() {
                        super("config", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }, {
                            no: 2,
                            name: "peerConnectionOptions",
                            kind: "message",
                            T: () => le
                        }, {
                            no: 3,
                            name: "protocolVersion",
                            kind: "scalar",
                            opt: !0,
                            T: 9
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            switch (t) {
                                case 1:
                                    i.type = e.string();
                                    break;
                                case 2:
                                    i.peerConnectionOptions = le.internalBinaryRead(e, e.uint32(), n, i.peerConnectionOptions);
                                    break;
                                case 3:
                                    i.protocolVersion = e.string();
                                    break;
                                default:
                                    let o = n.readUnknownField;
                                    if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                    let a = e.skip(s);
                                    !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type), e.peerConnectionOptions && le.internalBinaryWrite(e.peerConnectionOptions, t.tag(2, o.LengthDelimited).fork(), n).join(), void 0 !== e.protocolVersion && t.tag(3, o.LengthDelimited).string(e.protocolVersion);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const de = new class extends oe {
                    constructor() {
                        super("identify", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            if (1 === t) i.type = e.string();
                            else {
                                let o = n.readUnknownField;
                                if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                let a = e.skip(s);
                                !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const he = new class extends oe {
                    constructor() {
                        super("endpointId", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }, {
                            no: 2,
                            name: "id",
                            kind: "scalar",
                            T: 9
                        }, {
                            no: 3,
                            name: "protocolVersion",
                            kind: "scalar",
                            opt: !0,
                            T: 9
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", t.id = "", void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            switch (t) {
                                case 1:
                                    i.type = e.string();
                                    break;
                                case 2:
                                    i.id = e.string();
                                    break;
                                case 3:
                                    i.protocolVersion = e.string();
                                    break;
                                default:
                                    let o = n.readUnknownField;
                                    if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                    let a = e.skip(s);
                                    !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type), "" !== e.id && t.tag(2, o.LengthDelimited).string(e.id), void 0 !== e.protocolVersion && t.tag(3, o.LengthDelimited).string(e.protocolVersion);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const ue = new class extends oe {
                    constructor() {
                        super("endpointIdConfirm", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }, {
                            no: 2,
                            name: "committedId",
                            kind: "scalar",
                            T: 9
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", t.committedId = "", void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            switch (t) {
                                case 1:
                                    i.type = e.string();
                                    break;
                                case 2:
                                    i.committedId = e.string();
                                    break;
                                default:
                                    let o = n.readUnknownField;
                                    if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                    let a = e.skip(s);
                                    !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type), "" !== e.committedId && t.tag(2, o.LengthDelimited).string(e.committedId);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const me = new class extends oe {
                    constructor() {
                        super("streamerIdChanged", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }, {
                            no: 2,
                            name: "newID",
                            kind: "scalar",
                            T: 9
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", t.newID = "", void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            switch (t) {
                                case 1:
                                    i.type = e.string();
                                    break;
                                case 2:
                                    i.newID = e.string();
                                    break;
                                default:
                                    let o = n.readUnknownField;
                                    if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                    let a = e.skip(s);
                                    !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type), "" !== e.newID && t.tag(2, o.LengthDelimited).string(e.newID);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const pe = new class extends oe {
                    constructor() {
                        super("listStreamers", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            if (1 === t) i.type = e.string();
                            else {
                                let o = n.readUnknownField;
                                if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                let a = e.skip(s);
                                !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const ge = new class extends oe {
                    constructor() {
                        super("streamerList", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }, {
                            no: 2,
                            name: "ids",
                            kind: "scalar",
                            repeat: 2,
                            T: 9
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", t.ids = [], void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            switch (t) {
                                case 1:
                                    i.type = e.string();
                                    break;
                                case 2:
                                    i.ids.push(e.string());
                                    break;
                                default:
                                    let o = n.readUnknownField;
                                    if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                    let a = e.skip(s);
                                    !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type);
                        for (let n = 0; n < e.ids.length; n++) t.tag(2, o.LengthDelimited).string(e.ids[n]);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const fe = new class extends oe {
                    constructor() {
                        super("subscribe", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }, {
                            no: 2,
                            name: "streamerId",
                            kind: "scalar",
                            T: 9
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", t.streamerId = "", void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            switch (t) {
                                case 1:
                                    i.type = e.string();
                                    break;
                                case 2:
                                    i.streamerId = e.string();
                                    break;
                                default:
                                    let o = n.readUnknownField;
                                    if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                    let a = e.skip(s);
                                    !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type), "" !== e.streamerId && t.tag(2, o.LengthDelimited).string(e.streamerId);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const ye = new class extends oe {
                    constructor() {
                        super("unsubscribe", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            if (1 === t) i.type = e.string();
                            else {
                                let o = n.readUnknownField;
                                if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                let a = e.skip(s);
                                !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const ve = new class extends oe {
                    constructor() {
                        super("subscribeFailed", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }, {
                            no: 2,
                            name: "message",
                            kind: "scalar",
                            T: 9
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", t.message = "", void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            switch (t) {
                                case 1:
                                    i.type = e.string();
                                    break;
                                case 2:
                                    i.message = e.string();
                                    break;
                                default:
                                    let o = n.readUnknownField;
                                    if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                    let a = e.skip(s);
                                    !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type), "" !== e.message && t.tag(2, o.LengthDelimited).string(e.message);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const be = new class extends oe {
                    constructor() {
                        super("playerConnected", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }, {
                            no: 2,
                            name: "dataChannel",
                            kind: "scalar",
                            T: 8
                        }, {
                            no: 3,
                            name: "sfu",
                            kind: "scalar",
                            T: 8
                        }, {
                            no: 5,
                            name: "playerId",
                            kind: "scalar",
                            T: 9
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", t.dataChannel = !1, t.sfu = !1, t.playerId = "", void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            switch (t) {
                                case 1:
                                    i.type = e.string();
                                    break;
                                case 2:
                                    i.dataChannel = e.bool();
                                    break;
                                case 3:
                                    i.sfu = e.bool();
                                    break;
                                case 5:
                                    i.playerId = e.string();
                                    break;
                                default:
                                    let o = n.readUnknownField;
                                    if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                    let a = e.skip(s);
                                    !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type), !1 !== e.dataChannel && t.tag(2, o.Varint).bool(e.dataChannel), !1 !== e.sfu && t.tag(3, o.Varint).bool(e.sfu), "" !== e.playerId && t.tag(5, o.LengthDelimited).string(e.playerId);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const Se = new class extends oe {
                    constructor() {
                        super("playerDisconnected", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }, {
                            no: 2,
                            name: "playerId",
                            kind: "scalar",
                            T: 9
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", t.playerId = "", void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            switch (t) {
                                case 1:
                                    i.type = e.string();
                                    break;
                                case 2:
                                    i.playerId = e.string();
                                    break;
                                default:
                                    let o = n.readUnknownField;
                                    if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                    let a = e.skip(s);
                                    !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type), "" !== e.playerId && t.tag(2, o.LengthDelimited).string(e.playerId);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const Ce = new class extends oe {
                    constructor() {
                        super("offer", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }, {
                            no: 2,
                            name: "sdp",
                            kind: "scalar",
                            T: 9
                        }, {
                            no: 3,
                            name: "playerId",
                            kind: "scalar",
                            opt: !0,
                            T: 9
                        }, {
                            no: 4,
                            name: "sfu",
                            kind: "scalar",
                            opt: !0,
                            T: 8
                        }, {
                            no: 5,
                            name: "multiplex",
                            kind: "scalar",
                            opt: !0,
                            T: 8
                        }, {
                            no: 6,
                            name: "scalabilityMode",
                            kind: "scalar",
                            opt: !0,
                            T: 9
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", t.sdp = "", void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            switch (t) {
                                case 1:
                                    i.type = e.string();
                                    break;
                                case 2:
                                    i.sdp = e.string();
                                    break;
                                case 3:
                                    i.playerId = e.string();
                                    break;
                                case 4:
                                    i.sfu = e.bool();
                                    break;
                                case 5:
                                    i.multiplex = e.bool();
                                    break;
                                case 6:
                                    i.scalabilityMode = e.string();
                                    break;
                                default:
                                    let o = n.readUnknownField;
                                    if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                    let a = e.skip(s);
                                    !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type), "" !== e.sdp && t.tag(2, o.LengthDelimited).string(e.sdp), void 0 !== e.playerId && t.tag(3, o.LengthDelimited).string(e.playerId), void 0 !== e.sfu && t.tag(4, o.Varint).bool(e.sfu), void 0 !== e.multiplex && t.tag(5, o.Varint).bool(e.multiplex), void 0 !== e.scalabilityMode && t.tag(6, o.LengthDelimited).string(e.scalabilityMode);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const we = new class extends oe {
                    constructor() {
                        super("answer", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }, {
                            no: 2,
                            name: "sdp",
                            kind: "scalar",
                            T: 9
                        }, {
                            no: 3,
                            name: "playerId",
                            kind: "scalar",
                            opt: !0,
                            T: 9
                        }, {
                            no: 4,
                            name: "minBitrateBps",
                            kind: "scalar",
                            opt: !0,
                            T: 5
                        }, {
                            no: 5,
                            name: "maxBitrateBps",
                            kind: "scalar",
                            opt: !0,
                            T: 5
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", t.sdp = "", void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            switch (t) {
                                case 1:
                                    i.type = e.string();
                                    break;
                                case 2:
                                    i.sdp = e.string();
                                    break;
                                case 3:
                                    i.playerId = e.string();
                                    break;
                                case 4:
                                    i.minBitrateBps = e.int32();
                                    break;
                                case 5:
                                    i.maxBitrateBps = e.int32();
                                    break;
                                default:
                                    let o = n.readUnknownField;
                                    if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                    let a = e.skip(s);
                                    !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type), "" !== e.sdp && t.tag(2, o.LengthDelimited).string(e.sdp), void 0 !== e.playerId && t.tag(3, o.LengthDelimited).string(e.playerId), void 0 !== e.minBitrateBps && t.tag(4, o.Varint).int32(e.minBitrateBps), void 0 !== e.maxBitrateBps && t.tag(5, o.Varint).int32(e.maxBitrateBps);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const Ee = new class extends oe {
                    constructor() {
                        super("iceCandidateData", [{
                            no: 1,
                            name: "candidate",
                            kind: "scalar",
                            T: 9
                        }, {
                            no: 2,
                            name: "sdpMid",
                            kind: "scalar",
                            T: 9
                        }, {
                            no: 3,
                            name: "sdpMLineIndex",
                            kind: "scalar",
                            T: 5
                        }, {
                            no: 4,
                            name: "usernameFragment",
                            kind: "scalar",
                            opt: !0,
                            T: 9
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.candidate = "", t.sdpMid = "", t.sdpMLineIndex = 0, void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            switch (t) {
                                case 1:
                                    i.candidate = e.string();
                                    break;
                                case 2:
                                    i.sdpMid = e.string();
                                    break;
                                case 3:
                                    i.sdpMLineIndex = e.int32();
                                    break;
                                case 4:
                                    i.usernameFragment = e.string();
                                    break;
                                default:
                                    let o = n.readUnknownField;
                                    if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                    let a = e.skip(s);
                                    !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.candidate && t.tag(1, o.LengthDelimited).string(e.candidate), "" !== e.sdpMid && t.tag(2, o.LengthDelimited).string(e.sdpMid), 0 !== e.sdpMLineIndex && t.tag(3, o.Varint).int32(e.sdpMLineIndex), void 0 !== e.usernameFragment && t.tag(4, o.LengthDelimited).string(e.usernameFragment);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const Te = new class extends oe {
                    constructor() {
                        super("iceCandidate", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }, {
                            no: 2,
                            name: "candidate",
                            kind: "message",
                            T: () => Ee
                        }, {
                            no: 3,
                            name: "playerId",
                            kind: "scalar",
                            opt: !0,
                            T: 9
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            switch (t) {
                                case 1:
                                    i.type = e.string();
                                    break;
                                case 2:
                                    i.candidate = Ee.internalBinaryRead(e, e.uint32(), n, i.candidate);
                                    break;
                                case 3:
                                    i.playerId = e.string();
                                    break;
                                default:
                                    let o = n.readUnknownField;
                                    if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                    let a = e.skip(s);
                                    !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type), e.candidate && Ee.internalBinaryWrite(e.candidate, t.tag(2, o.LengthDelimited).fork(), n).join(), void 0 !== e.playerId && t.tag(3, o.LengthDelimited).string(e.playerId);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const Me = new class extends oe {
                    constructor() {
                        super("disconnectPlayer", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }, {
                            no: 2,
                            name: "playerId",
                            kind: "scalar",
                            T: 9
                        }, {
                            no: 3,
                            name: "reason",
                            kind: "scalar",
                            opt: !0,
                            T: 9
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", t.playerId = "", void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            switch (t) {
                                case 1:
                                    i.type = e.string();
                                    break;
                                case 2:
                                    i.playerId = e.string();
                                    break;
                                case 3:
                                    i.reason = e.string();
                                    break;
                                default:
                                    let o = n.readUnknownField;
                                    if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                    let a = e.skip(s);
                                    !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type), "" !== e.playerId && t.tag(2, o.LengthDelimited).string(e.playerId), void 0 !== e.reason && t.tag(3, o.LengthDelimited).string(e.reason);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const xe = new class extends oe {
                    constructor() {
                        super("ping", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }, {
                            no: 2,
                            name: "time",
                            kind: "scalar",
                            T: 5
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", t.time = 0, void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            switch (t) {
                                case 1:
                                    i.type = e.string();
                                    break;
                                case 2:
                                    i.time = e.int32();
                                    break;
                                default:
                                    let o = n.readUnknownField;
                                    if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                    let a = e.skip(s);
                                    !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type), 0 !== e.time && t.tag(2, o.Varint).int32(e.time);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const ke = new class extends oe {
                    constructor() {
                        super("pong", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }, {
                            no: 2,
                            name: "time",
                            kind: "scalar",
                            T: 5
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", t.time = 0, void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            switch (t) {
                                case 1:
                                    i.type = e.string();
                                    break;
                                case 2:
                                    i.time = e.int32();
                                    break;
                                default:
                                    let o = n.readUnknownField;
                                    if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                    let a = e.skip(s);
                                    !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type), 0 !== e.time && t.tag(2, o.Varint).int32(e.time);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const Re = new class extends oe {
                    constructor() {
                        super("streamerDisconnected", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            if (1 === t) i.type = e.string();
                            else {
                                let o = n.readUnknownField;
                                if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                let a = e.skip(s);
                                !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const Pe = new class extends oe {
                    constructor() {
                        super("layerPreference", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }, {
                            no: 2,
                            name: "spatialLayer",
                            kind: "scalar",
                            T: 5
                        }, {
                            no: 3,
                            name: "temporalLayer",
                            kind: "scalar",
                            T: 5
                        }, {
                            no: 4,
                            name: "playerId",
                            kind: "scalar",
                            T: 9
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", t.spatialLayer = 0, t.temporalLayer = 0, t.playerId = "", void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            switch (t) {
                                case 1:
                                    i.type = e.string();
                                    break;
                                case 2:
                                    i.spatialLayer = e.int32();
                                    break;
                                case 3:
                                    i.temporalLayer = e.int32();
                                    break;
                                case 4:
                                    i.playerId = e.string();
                                    break;
                                default:
                                    let o = n.readUnknownField;
                                    if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                    let a = e.skip(s);
                                    !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type), 0 !== e.spatialLayer && t.tag(2, o.Varint).int32(e.spatialLayer), 0 !== e.temporalLayer && t.tag(3, o.Varint).int32(e.temporalLayer), "" !== e.playerId && t.tag(4, o.LengthDelimited).string(e.playerId);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const Ie = new class extends oe {
                    constructor() {
                        super("dataChannelRequest", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            if (1 === t) i.type = e.string();
                            else {
                                let o = n.readUnknownField;
                                if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                let a = e.skip(s);
                                !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const Le = new class extends oe {
                    constructor() {
                        super("peerDataChannels", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }, {
                            no: 2,
                            name: "playerId",
                            kind: "scalar",
                            T: 9
                        }, {
                            no: 3,
                            name: "sendStreamId",
                            kind: "scalar",
                            T: 5
                        }, {
                            no: 4,
                            name: "recvStreamId",
                            kind: "scalar",
                            T: 5
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", t.playerId = "", t.sendStreamId = 0, t.recvStreamId = 0, void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            switch (t) {
                                case 1:
                                    i.type = e.string();
                                    break;
                                case 2:
                                    i.playerId = e.string();
                                    break;
                                case 3:
                                    i.sendStreamId = e.int32();
                                    break;
                                case 4:
                                    i.recvStreamId = e.int32();
                                    break;
                                default:
                                    let o = n.readUnknownField;
                                    if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                    let a = e.skip(s);
                                    !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type), "" !== e.playerId && t.tag(2, o.LengthDelimited).string(e.playerId), 0 !== e.sendStreamId && t.tag(3, o.Varint).int32(e.sendStreamId), 0 !== e.recvStreamId && t.tag(4, o.Varint).int32(e.recvStreamId);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const Oe = new class extends oe {
                    constructor() {
                        super("peerDataChannelsReady", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            if (1 === t) i.type = e.string();
                            else {
                                let o = n.readUnknownField;
                                if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                let a = e.skip(s);
                                !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const Fe = new class extends oe {
                    constructor() {
                        super("streamerDataChannels", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }, {
                            no: 2,
                            name: "sfuId",
                            kind: "scalar",
                            T: 9
                        }, {
                            no: 3,
                            name: "sendStreamId",
                            kind: "scalar",
                            T: 5
                        }, {
                            no: 4,
                            name: "recvStreamId",
                            kind: "scalar",
                            T: 5
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", t.sfuId = "", t.sendStreamId = 0, t.recvStreamId = 0, void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            switch (t) {
                                case 1:
                                    i.type = e.string();
                                    break;
                                case 2:
                                    i.sfuId = e.string();
                                    break;
                                case 3:
                                    i.sendStreamId = e.int32();
                                    break;
                                case 4:
                                    i.recvStreamId = e.int32();
                                    break;
                                default:
                                    let o = n.readUnknownField;
                                    if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                    let a = e.skip(s);
                                    !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type), "" !== e.sfuId && t.tag(2, o.LengthDelimited).string(e.sfuId), 0 !== e.sendStreamId && t.tag(3, o.Varint).int32(e.sendStreamId), 0 !== e.recvStreamId && t.tag(4, o.Varint).int32(e.recvStreamId);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const De = new class extends oe {
                    constructor() {
                        super("startStreaming", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            if (1 === t) i.type = e.string();
                            else {
                                let o = n.readUnknownField;
                                if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                let a = e.skip(s);
                                !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const Ae = new class extends oe {
                    constructor() {
                        super("stopStreaming", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            if (1 === t) i.type = e.string();
                            else {
                                let o = n.readUnknownField;
                                if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                let a = e.skip(s);
                                !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const _e = new class extends oe {
                    constructor() {
                        super("playerCount", [{
                            no: 1,
                            name: "type",
                            kind: "scalar",
                            T: 9
                        }, {
                            no: 2,
                            name: "count",
                            kind: "scalar",
                            T: 5
                        }])
                    }
                    create(e) {
                        const t = globalThis.Object.create(this.messagePrototype);
                        return t.type = "", t.count = 0, void 0 !== e && u(this, t, e), t
                    }
                    internalBinaryRead(e, t, n, s) {
                        let i = null != s ? s : this.create(),
                            o = e.pos + t;
                        for (; e.pos < o;) {
                            let [t, s] = e.tag();
                            switch (t) {
                                case 1:
                                    i.type = e.string();
                                    break;
                                case 2:
                                    i.count = e.int32();
                                    break;
                                default:
                                    let o = n.readUnknownField;
                                    if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                    let a = e.skip(s);
                                    !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                            }
                        }
                        return i
                    }
                    internalBinaryWrite(e, t, n) {
                        "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type), 0 !== e.count && t.tag(2, o.Varint).int32(e.count);
                        let s = n.writeUnknownFields;
                        return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                    }
                };
                const Ve = new class extends oe {
                        constructor() {
                            super("stats", [{
                                no: 1,
                                name: "type",
                                kind: "scalar",
                                T: 9
                            }, {
                                no: 2,
                                name: "data",
                                kind: "scalar",
                                T: 9
                            }])
                        }
                        create(e) {
                            const t = globalThis.Object.create(this.messagePrototype);
                            return t.type = "", t.data = "", void 0 !== e && u(this, t, e), t
                        }
                        internalBinaryRead(e, t, n, s) {
                            let i = null != s ? s : this.create(),
                                o = e.pos + t;
                            for (; e.pos < o;) {
                                let [t, s] = e.tag();
                                switch (t) {
                                    case 1:
                                        i.type = e.string();
                                        break;
                                    case 2:
                                        i.data = e.string();
                                        break;
                                    default:
                                        let o = n.readUnknownField;
                                        if ("throw" === o) throw new globalThis.Error(`Unknown field ${t} (wire type ${s}) for ${this.typeName}`);
                                        let a = e.skip(s);
                                        !1 !== o && (!0 === o ? r.onRead : o)(this.typeName, i, t, s, a)
                                }
                            }
                            return i
                        }
                        internalBinaryWrite(e, t, n) {
                            "" !== e.type && t.tag(1, o.LengthDelimited).string(e.type), "" !== e.data && t.tag(2, o.LengthDelimited).string(e.data);
                            let s = n.writeUnknownFields;
                            return !1 !== s && (1 == s ? r.onWrite : s)(this.typeName, e, t), t
                        }
                    },
                    Ne = {
                        answer: we,
                        config: ce,
                        disconnectPlayer: Me,
                        endpointId: he,
                        endpointIdConfirm: ue,
                        iceCandidate: Te,
                        identify: de,
                        listStreamers: pe,
                        offer: Ce,
                        ping: xe,
                        playerConnected: be,
                        playerCount: _e,
                        playerDisconnected: Se,
                        pong: ke,
                        stats: Ve,
                        streamerDisconnected: Re,
                        streamerList: ge,
                        subscribe: fe,
                        unsubscribe: ye,
                        layerPreference: Pe,
                        dataChannelRequest: Ie,
                        peerDataChannels: Le,
                        peerDataChannelsReady: Oe,
                        streamerDataChannels: Fe,
                        startStreaming: De,
                        stopStreaming: Ae
                    };

                function Ue(e, t) {
                    const n = e.create();
                    return n.type = e.typeName, t && e.mergePartial(n, t), n
                }

                function Be(e) {
                    let t = !0;
                    if (!e.type) return a.Vy.Error(`Parsed message has no type. Rejected. ${JSON.stringify(e)}`), null;
                    const n = Ne[e.type];
                    if (!n) return a.Vy.Error(`Message is of an unknown type: "${e.type}". Rejected.`), null;
                    if (n.fields)
                        for (const s of n.fields) s.opt || Object.prototype.hasOwnProperty.call(e, s.name) || (a.Vy.Error(`Message "${e.type}"" is missing required field "${s.name}". Rejected.`), t = !1);
                    for (const s in e) {
                        n.fields.find((e => e.name === s)) || (a.Vy.Error(`Message "${e.type}" contains unknown field "${s}". Rejected.`), t = !1)
                    }
                    return t ? n : null
                }
                class We {
                    get RTT() {
                        return this.rtt
                    }
                    constructor(e, t) {
                        this.alive = !1, this.rtt = 0, this.protocol = e, this.timeout = t, this.onResponse = this.onHeartbeatResponse.bind(this), this.protocol.transport.on("close", this.stop.bind(this)), this.start()
                    }
                    start() {
                        this.alive = !0, this.protocol.on("pong", this.onResponse), this.keepalive = setInterval(this.sendHeartbeat.bind(this), this.timeout)
                    }
                    stop() {
                        clearInterval(this.keepalive), this.protocol.off("pong", this.onResponse)
                    }
                    sendHeartbeat() {
                        var e;
                        !1 !== this.alive ? (this.alive = !1, this.protocol.sendMessage(Ue(xe, {
                            time: (new Date).getTime()
                        }))) : null === (e = this.onTimeout) || void 0 === e || e.call(this)
                    }
                    onHeartbeatResponse(e) {
                        this.rtt = (new Date).getTime() - e.time, this.alive = !0
                    }
                }
                class ze {
                    constructor(e) {
                        this.videoElementProvider = e, this.audioElement = document.createElement("Audio"), this.videoElementProvider.setAudioElement(this.audioElement)
                    }
                    handleOnTrack(e) {
                        if (a.Vy.Info("handleOnTrack " + JSON.stringify(e.streams)), e.streams.length < 1 || "probator" == e.streams[0].id) return;
                        const t = this.videoElementProvider.getVideoElement();
                        if (e.track && a.Vy.Info("Got track - " + e.track.kind + " id=" + e.track.id + " readyState=" + e.track.readyState), "audio" != e.track.kind) return "video" == e.track.kind && t.srcObject !== e.streams[0] ? (t.srcObject = e.streams[0], void a.Vy.Info("Set video source from video track ontrack.")) : void 0;
                        this.CreateAudioTrack(e.streams[0])
                    }
                    CreateAudioTrack(e) {
                        const t = this.videoElementProvider.getVideoElement();
                        t.srcObject != e && t.srcObject && t.srcObject !== e && (this.audioElement.srcObject = e, a.Vy.Info("Created new audio element to play separate audio stream."))
                    }
                }
                class He {
                    constructor(e) {
                        this.freezeFrameHeight = 0, this.freezeFrameWidth = 0, this.rootDiv = e, this.rootElement = document.createElement("div"), this.rootElement.id = "freezeFrame", this.rootElement.style.display = "none", this.rootElement.style.pointerEvents = "none", this.rootElement.style.position = "absolute", this.rootElement.style.zIndex = "20", this.imageElement = document.createElement("img"), this.imageElement.style.position = "absolute", this.rootElement.appendChild(this.imageElement), this.rootDiv.appendChild(this.rootElement)
                    }
                    setElementForShow() {
                        this.rootElement.style.display = "block"
                    }
                    setElementForHide() {
                        this.rootElement.style.display = "none"
                    }
                    updateImageElementSource(e) {
                        const t = btoa(e.reduce(((e, t) => e + String.fromCharCode(t)), ""));
                        this.imageElement.src = "data:image/jpeg;base64," + t
                    }
                    setDimensionsFromElementAndResize() {
                        this.freezeFrameHeight = this.imageElement.naturalHeight, this.freezeFrameWidth = this.imageElement.naturalWidth, this.resize()
                    }
                    resize() {
                        if (0 !== this.freezeFrameWidth && 0 !== this.freezeFrameHeight) {
                            let e = 0,
                                t = 0,
                                n = 0,
                                s = 0;
                            const i = this.rootDiv.clientWidth / this.rootDiv.clientHeight,
                                r = this.freezeFrameWidth / this.freezeFrameHeight;
                            i < r ? (e = this.rootDiv.clientWidth, t = Math.floor(this.rootDiv.clientWidth / r), n = Math.floor(.5 * (this.rootDiv.clientHeight - t)), s = 0) : (e = Math.floor(this.rootDiv.clientHeight * r), t = this.rootDiv.clientHeight, n = 0, s = Math.floor(.5 * (this.rootDiv.clientWidth - e))), this.rootElement.style.width = this.rootDiv.offsetWidth + "px", this.rootElement.style.height = this.rootDiv.offsetHeight + "px", this.rootElement.style.left = "0px", this.rootElement.style.top = "0px", this.imageElement.style.width = e + "px", this.imageElement.style.height = t + "px", this.imageElement.style.left = s + "px", this.imageElement.style.top = n + "px"
                        }
                    }
                }
                class je {
                    constructor(e) {
                        this.receiving = !1, this.size = 0, this.jpeg = void 0, this.valid = !1, this.freezeFrameDelay = 50, this.freezeFrame = new He(e)
                    }
                    showFreezeFrame() {
                        this.valid && this.freezeFrame.setElementForShow()
                    }
                    hideFreezeFrame() {
                        this.valid = !1, this.freezeFrame.setElementForHide()
                    }
                    updateFreezeFrameAndShow(e, t) {
                        this.freezeFrame.updateImageElementSource(e), this.freezeFrame.imageElement.onload = () => {
                            this.freezeFrame.setDimensionsFromElementAndResize(), t()
                        }
                    }
                    processFreezeFrameMessage(e, t) {
                        this.receiving || (this.receiving = !0, this.valid = !1, this.size = 0, this.jpeg = void 0), this.size = new DataView(e.slice(1, 5).buffer).getInt32(0, !0);
                        const n = e.slice(5);
                        if (this.jpeg) {
                            const e = new Uint8Array(this.jpeg.length + n.length);
                            e.set(this.jpeg, 0), e.set(n, this.jpeg.length), this.jpeg = e
                        } else this.jpeg = n, this.receiving = !0, a.Vy.Info(`received first chunk of freeze frame: ${this.jpeg.length}/${this.size}`);
                        this.jpeg.length === this.size ? (this.receiving = !1, this.valid = !0, a.Vy.Info(`received complete freeze frame ${this.size}`), this.updateFreezeFrameAndShow(this.jpeg, t)) : this.jpeg.length > this.size && (a.Vy.Error(`received bigger freeze frame than advertised: ${this.jpeg.length}/${this.size}`), this.jpeg = void 0, this.receiving = !1)
                    }
                }
                var Qe = n(442),
                    $e = n(656);
                class Ke {
                    constructor(e, t, n) {
                        this.active = !1, this.countdownActive = !1, this.warnTimer = void 0, this.countDown = 0, this.countDownTimer = void 0, this.config = e, this.pixelStreaming = t, this.onDismissAfk = n, this.onAFKTimedOutCallback = () => {
                            console.log("AFK timed out, did you want to override this callback?")
                        }
                    }
                    onAfkClick() {
                        clearInterval(this.countDownTimer), (this.active || this.countdownActive) && (this.startAfkWarningTimer(), this.pixelStreaming.dispatchEvent(new $e.jr))
                    }
                    startAfkWarningTimer() {
                        this.config.getNumericSettingValue(Qe.k$.AFKTimeoutSecs) > 0 && this.config.isFlagEnabled(Qe.iI.AFKDetection) ? this.active = !0 : this.active = !1, this.resetAfkWarningTimer()
                    }
                    stopAfkWarningTimer() {
                        this.active = !1, this.countdownActive = !1, clearTimeout(this.warnTimer), clearInterval(this.countDownTimer)
                    }
                    pauseAfkWarningTimer() {
                        this.active = !1
                    }
                    resetAfkWarningTimer() {
                        this.active && this.config.isFlagEnabled(Qe.iI.AFKDetection) && (clearTimeout(this.warnTimer), this.warnTimer = setTimeout((() => this.activateAfkEvent()), 1e3 * this.config.getNumericSettingValue(Qe.k$.AFKTimeoutSecs)))
                    }
                    activateAfkEvent() {
                        this.pauseAfkWarningTimer(), this.pixelStreaming.dispatchEvent(new $e.mC({
                            countDown: this.countDown,
                            dismissAfk: this.onDismissAfk
                        })), this.countDown = this.config.getNumericSettingValue(Qe.k$.AFKCountdownSecs), this.countdownActive = !0, this.pixelStreaming.dispatchEvent(new $e.S_({
                            countDown: this.countDown
                        })), this.config.isFlagEnabled(Qe.iI.HoveringMouseMode) || document.exitPointerLock && document.exitPointerLock(), this.countDownTimer = setInterval((() => {
                            this.countDown--, 0 == this.countDown ? (this.pixelStreaming.dispatchEvent(new $e.Kr), this.onAFKTimedOutCallback(), a.Vy.Info("You have been disconnected due to inactivity"), this.stopAfkWarningTimer()) : this.pixelStreaming.dispatchEvent(new $e.S_({
                                countDown: this.countDown
                            }))
                        }), 1e3)
                    }
                }
                class Ge {
                    constructor() {
                        this.isReceivingFreezeFrame = !1
                    }
                    getDataChannelInstance() {
                        return this
                    }
                    createDataChannel(e, t, n) {
                        this.peerConnection = e, this.label = t, this.datachannelOptions = n, null == n && (this.datachannelOptions = {}, this.datachannelOptions.ordered = !0), this.dataChannel = this.peerConnection.createDataChannel(this.label, this.datachannelOptions), this.setupDataChannel()
                    }
                    setupDataChannel() {
                        this.dataChannel.binaryType = "arraybuffer", this.dataChannel.onopen = e => this.handleOnOpen(e), this.dataChannel.onclose = e => this.handleOnClose(e), this.dataChannel.onmessage = e => this.handleOnMessage(e), this.dataChannel.onerror = e => this.handleOnError(e)
                    }
                    handleOnOpen(e) {
                        var t;
                        a.Vy.Info(`Data Channel (${this.label}) opened.`), this.onOpen(null === (t = this.dataChannel) || void 0 === t ? void 0 : t.label, e)
                    }
                    handleOnClose(e) {
                        var t;
                        a.Vy.Info(`Data Channel (${this.label}) closed.`), this.onClose(null === (t = this.dataChannel) || void 0 === t ? void 0 : t.label, e)
                    }
                    handleOnMessage(e) {
                        a.Vy.Info(`Data Channel (${this.label}) message: ${e}`)
                    }
                    handleOnError(e) {
                        var t;
                        a.Vy.Info(`Data Channel (${this.label}) error: ${e}`), this.onError(null === (t = this.dataChannel) || void 0 === t ? void 0 : t.label, e)
                    }
                    onOpen(e, t) {}
                    onClose(e, t) {}
                    onError(e, t) {}
                }
                class qe {}
                class Xe {}
                class Je {}
                class Ye {}
                class Ze {}
                class et {}
                class tt {}
                class nt {}
                class st {
                    constructor() {
                        this.inboundVideoStats = new Xe, this.inboundAudioStats = new qe, this.datachannelStats = new Je, this.outboundVideoStats = new Ze, this.outboundAudioStats = new Ze, this.remoteOutboundAudioStats = new et, this.remoteOutboundVideoStats = new et, this.sessionStats = new tt, this.streamStats = new nt, this.codecs = new Map
                    }
                    processStats(e) {
                        this.localCandidates = new Array, this.remoteCandidates = new Array, this.candidatePairs = new Array, e.forEach((e => {
                            switch (e.type) {
                                case "candidate-pair":
                                    this.handleCandidatePair(e);
                                    break;
                                case "certificate":
                                case "media-source":
                                case "media-playout":
                                case "peer-connection":
                                case "remote-inbound-rtp":
                                    // this.handleRemoteInboundRTP(e);
                                    break;
                                case "codec":
                                    this.handleCodec(e);
                                    break;
                                case "data-channel":
                                    this.handleDataChannel(e);
                                    break;
                                case "inbound-rtp":
                                    this.handleInboundRTP(e);
                                    break;
                                case "local-candidate":
                                    this.handleLocalCandidate(e);
                                    break;
                                case "outbound-rtp":
                                    this.handleLocalOutbound(e);
                                    break;
                                case "remote-candidate":
                                    this.handleRemoteCandidate(e);
                                    break;
                                case "remote-outbound-rtp":
                                    this.handleRemoteOutbound(e);
                                    break;
                                case "track":
                                    this.handleTrack(e);
                                    break;
                                case "transport":
                                    this.handleTransport(e);
                                    break;
                                case "stream":
                                    this.handleStream(e);
                                    break;
                                default:
                                    a.Vy.Error("unhandled Stat Type"), a.Vy.Info(e)
                            }
                        }))
                    }
                    handleStream(e) {
                        this.streamStats = e
                    }
                    handleCandidatePair(e) {
                        this.candidatePairs.push(e)
                    }
                    handleDataChannel(e) {
                        this.datachannelStats.bytesReceived = e.bytesReceived, this.datachannelStats.bytesSent = e.bytesSent, this.datachannelStats.dataChannelIdentifier = e.dataChannelIdentifier, this.datachannelStats.id = e.id, this.datachannelStats.label = e.label, this.datachannelStats.messagesReceived = e.messagesReceived, this.datachannelStats.messagesSent = e.messagesSent, this.datachannelStats.protocol = e.protocol, this.datachannelStats.state = e.state, this.datachannelStats.timestamp = e.timestamp
                    }
                    handleLocalCandidate(e) {
                        const t = new Ye;
                        t.label = "local-candidate", t.address = e.address, t.port = e.port, t.protocol = e.protocol, t.candidateType = e.candidateType, t.id = e.id, t.relayProtocol = e.relayProtocol, t.transportId = e.transportId, this.localCandidates.push(t)
                    }
                    handleRemoteCandidate(e) {
                        const t = new Ye;
                        t.label = "remote-candidate", t.address = e.address, t.port = e.port, t.protocol = e.protocol, t.id = e.id, t.candidateType = e.candidateType, t.relayProtocol = e.relayProtocol, t.transportId = e.transportId, this.remoteCandidates.push(t)
                    }
                    handleInboundRTP(e) {
                        switch (e.kind) {
                            case "video":
                                e.bytesReceived > this.inboundVideoStats.bytesReceived && e.timestamp > this.inboundVideoStats.timestamp && (this.inboundVideoStats.bitrate = 8 * (e.bytesReceived - this.inboundVideoStats.bytesReceived) / (e.timestamp - this.inboundVideoStats.timestamp), this.inboundVideoStats.bitrate = Math.floor(this.inboundVideoStats.bitrate));
                                for (const t in e) this.inboundVideoStats[t] = e[t];
                                break;
                            case "audio":
                                e.bytesReceived > this.inboundAudioStats.bytesReceived && e.timestamp > this.inboundAudioStats.timestamp && (this.inboundAudioStats.bitrate = 8 * (e.bytesReceived - this.inboundAudioStats.bytesReceived) / (e.timestamp - this.inboundAudioStats.timestamp), this.inboundAudioStats.bitrate = Math.floor(this.inboundAudioStats.bitrate));
                                for (const t in e) this.inboundAudioStats[t] = e[t];
                                break;
                            default:
                                a.Vy.Error(`Kind should be audio or video, we got ${e.kind} - that's unsupported.`)
                        }
                    }
                    // handleRemoteInboundRTP(e){
                    //     if (e.kind === "video") {
                    //         this.remoteInboundVideoStats = e;
                    //     } else if (e.kind === "audio") {
                    //         this.remoteInboundAudioStats = e;
                    //     } else {
                    //         console.warn(`Unhandled remote-inbound-rtp kind: ${e.kind}`);
                    //     }
                    // }
                    handleLocalOutbound(e) {
                        const t = "audio" === e.kind ? this.outboundAudioStats : this.outboundVideoStats;
                        t.active = e.active, t.codecId = e.codecId, t.bytesSent = e.bytesSent, t.frameHeight = e.frameHeight, t.frameWidth = e.frameWidth, t.framesEncoded = e.framesEncoded, t.framesPerSecond = e.framesPerSecond, t.headerBytesSent = e.headerBytesSent, t.id = e.id, t.keyFramesEncoded = e.keyFramesEncoded, t.kind = e.kind, t.mediaSourceId = e.mediaSourceId, t.mid = e.mid, t.nackCount = e.nackCount, t.packetsSent = e.packetsSent, t.qpSum = e.qpSum, t.qualityLimitationDurations = e.qualityLimitationDurations, t.qualityLimitationReason = e.qualityLimitationReason, t.remoteId = e.remoteId, t.retransmittedBytesSent = e.retransmittedBytesSent, t.rid = e.rid, t.scalabilityMode = e.scalabilityMode, t.ssrc = e.ssrc, t.targetBitrate = e.targetBitrate, t.timestamp = e.timestamp, t.totalEncodeTime = e.totalEncodeTime, t.totalEncodeBytesTarget = e.totalEncodeBytesTarget, t.totalPacketSendDelay = e.totalPacketSendDelay, t.transportId = e.transportId
                    }
                    handleRemoteOutbound(e) {
                        const t = "audio" === e.kind ? this.remoteOutboundAudioStats : this.remoteOutboundVideoStats;
                        t.bytesSent = e.bytesSent, t.codecId = e.codecId, t.id = e.id, t.kind = e.kind, t.localId = e.localId, t.packetsSent = e.packetsSent, t.remoteTimestamp = e.remoteTimestamp, t.reportsSent = e.reportsSent, t.roundTripTimeMeasurements = e.roundTripTimeMeasurements, t.ssrc = e.ssrc, t.timestamp = e.timestamp, t.totalRoundTripTime = e.totalRoundTripTime, t.transportId = e.transportId
                    }
                    handleTrack(e) {
                        "track" !== e.type || "video_label" !== e.trackIdentifier && "video" !== e.kind || (this.inboundVideoStats.framesDropped = e.framesDropped, this.inboundVideoStats.framesReceived = e.framesReceived, this.inboundVideoStats.frameHeight = e.frameHeight, this.inboundVideoStats.frameWidth = e.frameWidth)
                    }
                    handleTransport(e) {
                        this.transportStats = e
                    }
                    handleCodec(e) {
                        const t = e.id;
                        this.codecs.set(t, e)
                    }
                    handleSessionStatistics(e, t, n) {
                        const s = Date.now() - e;
                        this.sessionStats.runTime = new Date(s).toISOString().substr(11, 8).toString();
                        const i = null === t ? "Not sent yet" : t ? "true" : "false";
                        this.sessionStats.controlsStreamInput = i, this.sessionStats.videoEncoderAvgQP = n
                    }
                    isNumber(e) {
                        return "number" == typeof e && isFinite(e)
                    }
                    getActiveCandidatePair() {
                        if (void 0 === this.candidatePairs) return null;
                        if (this.transportStats) {
                            const e = this.candidatePairs.find((e => e.id === this.transportStats.selectedCandidatePairId));
                            return void 0 === e ? null : e
                        }
                        const e = this.candidatePairs.find((e => e.selected));
                        return void 0 === e ? null : e
                    }
                }
                var it = n(585);
                class rt {
                    static isVideoTransceiver(e) {
                        return this.canTransceiverReceiveVideo(e) || this.canTransceiverSendVideo(e)
                    }
                    static canTransceiverReceiveVideo(e) {
                        return !!e && ("sendrecv" === e.direction || "recvonly" === e.direction) && e.receiver && e.receiver.track && "video" === e.receiver.track.kind
                    }
                    static canTransceiverSendVideo(e) {
                        return !!e && ("sendrecv" === e.direction || "sendonly" === e.direction) && e.sender && e.sender.track && "video" === e.sender.track.kind
                    }
                    static isAudioTransceiver(e) {
                        return this.canTransceiverReceiveAudio(e) || this.canTransceiverSendAudio(e)
                    }
                    static canTransceiverReceiveAudio(e) {
                        return !!e && ("sendrecv" === e.direction || "recvonly" === e.direction) && e.receiver && e.receiver.track && "audio" === e.receiver.track.kind
                    }
                    static canTransceiverSendAudio(e) {
                        return !!e && ("sendrecv" === e.direction || "sendonly" === e.direction) && e.sender && e.sender.track && "audio" === e.sender.track.kind
                    }
                }
                class ot {
                    static addVideoHeaderExtensionToSdp(e, t) {
                        const n = e.split("\n").filter((e => e.startsWith("a=extmap:"))).map((e => parseInt(e.split(" ")[0].substring(9), 10))).sort(((e, t) => e - t)).filter(((e, t, n) => n.indexOf(e) === t)),
                            s = "a=extmap:" + (n[n.length - 1] + 1) + " " + t + "\r\n",
                            i = e.split("\nm=").map(((e, t) => (t > 0 ? "m=" + e : e).trim() + "\r\n"));
                        return i.shift() + i.map((e => e.startsWith("m=video") ? e + s : e)).join("")
                    }
                }
                class at {}
                class lt {}
                class ct {
                    constructor() {
                        this.latestSenderRecvClockOffset = null
                    }
                    calculate(e, t) {
                        const n = new dt,
                            s = this.getRTTMs(e);
                        if (null != s) {
                            n.rttMs = s;
                            const i = this.getCaptureSource(t);
                            if (null != i) {
                                const t = this.calculateSenderLatency(e, i);
                                null !== t && (n.senderLatencyMs = t)
                            }
                        }
                        return void 0 !== e.inboundVideoStats.totalProcessingDelay && void 0 !== e.inboundVideoStats.framesDecoded && (n.averageProcessingDelayMs = e.inboundVideoStats.totalProcessingDelay / e.inboundVideoStats.framesDecoded * 1e3), void 0 !== e.inboundVideoStats.jitterBufferDelay && void 0 !== e.inboundVideoStats.jitterBufferEmittedCount && (n.averageJitterBufferDelayMs = e.inboundVideoStats.jitterBufferDelay / e.inboundVideoStats.jitterBufferEmittedCount * 1e3), void 0 !== e.inboundVideoStats.framesDecoded && void 0 !== e.inboundVideoStats.totalDecodeTime && (n.averageDecodeLatencyMs = e.inboundVideoStats.totalDecodeTime / e.inboundVideoStats.framesDecoded * 1e3), void 0 !== e.inboundVideoStats.totalAssemblyTime && void 0 !== e.inboundVideoStats.framesAssembledFromMultiplePackets && (n.averageAssemblyDelayMs = e.inboundVideoStats.totalAssemblyTime / e.inboundVideoStats.framesAssembledFromMultiplePackets * 1e3), void 0 !== e.inboundVideoStats.googTimingFrameInfo && e.inboundVideoStats.googTimingFrameInfo.length > 0 && (n.frameTiming = this.extractFrameTimingInfo(e.inboundVideoStats.googTimingFrameInfo)), void 0 !== n.frameTiming && void 0 !== n.frameTiming.captureToSendLatencyMs && void 0 !== n.averageProcessingDelayMs && void 0 !== n.rttMs && (n.averageE2ELatency = n.frameTiming.captureToSendLatencyMs + .5 * n.rttMs + n.averageProcessingDelayMs), null != n.senderLatencyMs && void 0 !== n.averageProcessingDelayMs && void 0 !== n.rttMs && (n.averageE2ELatency = n.senderLatencyMs + .5 * n.rttMs + n.averageProcessingDelayMs), n
                    }
                    extractFrameTimingInfo(e) {
                        const t = new lt,
                            n = e.split(",");
                        return 15 === n.length && (t.rtpTimestamp = Number.parseInt(n[0]), t.captureTimestamp = Number.parseInt(n[1]), t.encodeStartTimestamp = Number.parseInt(n[2]), t.encodeFinishTimestamp = Number.parseInt(n[3]), t.packetizerFinishTimestamp = Number.parseInt(n[4]), t.pacerExitTimestamp = Number.parseInt(n[5]), t.networkTimestamp1 = Number.parseInt(n[6]), t.networkTimestamp2 = Number.parseInt(n[7]), t.receiveStart = Number.parseInt(n[8]), t.receiveFinish = Number.parseInt(n[9]), t.decodeStart = Number.parseInt(n[10]), t.decodeFinish = Number.parseInt(n[11]), t.renderTime = Number.parseInt(n[12]), t.isOutlier = Number.parseInt(n[13]) > 0, t.isTriggeredByTimer = Number.parseInt(n[14]) > 0, t.encoderLatencyMs = t.encodeFinishTimestamp - t.encodeStartTimestamp, t.packetizeLatencyMs = t.packetizerFinishTimestamp - t.encodeFinishTimestamp, t.pacerLatencyMs = t.pacerExitTimestamp - t.packetizerFinishTimestamp, t.captureToSendLatencyMs = t.pacerExitTimestamp - t.captureTimestamp), t
                    }
                    calculateSenderLatency(e, t) {
                        const n = t.captureTimestamp + t.senderCaptureTimeOffset;
                        let s = this.calculateSenderReceiverClockOffset(e);
                        if (null == s) {
                            if (null == this.latestSenderRecvClockOffset) return null;
                            s = this.latestSenderRecvClockOffset
                        } else this.latestSenderRecvClockOffset = s;
                        const i = n + s - 22089888e5;
                        return t.timestamp - i
                    }
                    getCaptureSource(e) {
                        e = e.filter((e => "video" === e.track.kind));
                        for (const t of e) {
                            const e = t.getSynchronizationSources().concat(t.getContributingSources());
                            for (const t of e)
                                if (void 0 !== t.captureTimestamp && void 0 !== t.senderCaptureTimeOffset && void 0 !== t.timestamp) {
                                    const e = new at;
                                    return e.timestamp = t.timestamp, e.captureTimestamp = t.captureTimestamp, e.senderCaptureTimeOffset = t.senderCaptureTimeOffset, e
                                }
                        }
                        return null
                    }
                    calculateSenderReceiverClockOffset(e) {
                        if (!(void 0 !== e.remoteOutboundVideoStats && void 0 !== e.remoteOutboundVideoStats.timestamp && void 0 !== e.remoteOutboundVideoStats.remoteTimestamp)) return null;
                        const t = e.remoteOutboundVideoStats.timestamp,
                            n = e.remoteOutboundVideoStats.remoteTimestamp,
                            s = this.getRTTMs(e);
                        if (void 0 !== t && void 0 !== n && null !== s) {
                            return t - (n + .5 * s)
                        }
                        return null
                    }
                    getRTTMs(e) {
                        const t = e.getActiveCandidatePair();
                        if (t && void 0 !== t.currentRoundTripTime) {
                            return 1e3 * t.currentRoundTripTime
                        }
                        if (e.remoteOutboundVideoStats && void 0 !== e.remoteOutboundVideoStats.totalRoundTripTime && void 0 !== e.remoteOutboundVideoStats.roundTripTimeMeasurements && e.remoteOutboundVideoStats.roundTripTimeMeasurements > 0) {
                            return 1e3 * (e.remoteOutboundVideoStats.totalRoundTripTime / e.remoteOutboundVideoStats.roundTripTimeMeasurements)
                        }
                        if (e.remoteOutboundAudioStats && void 0 !== e.remoteOutboundAudioStats.totalRoundTripTime && void 0 !== e.remoteOutboundAudioStats.roundTripTimeMeasurements && e.remoteOutboundAudioStats.roundTripTimeMeasurements > 0) {
                            return 1e3 * (e.remoteOutboundAudioStats.totalRoundTripTime / e.remoteOutboundAudioStats.roundTripTimeMeasurements)
                        }
                        return null
                    }
                }
                class dt {
                    constructor() {
                        this.senderLatencyMs = void 0, this.senderLatencyAbsCaptureTimeMs = void 0, this.rttMs = void 0, this.averageProcessingDelayMs = void 0, this.averageJitterBufferDelayMs = void 0, this.averageDecodeLatencyMs = void 0, this.averageAssemblyDelayMs = void 0, this.averageE2ELatency = void 0, this.frameTiming = void 0
                    }
                }
                var ht = function(e, t, n, s) {
                    return new(n || (n = Promise))((function(i, r) {
                        function o(e) {
                            try {
                                l(s.next(e))
                            } catch (e) {
                                r(e)
                            }
                        }

                        function a(e) {
                            try {
                                l(s.throw(e))
                            } catch (e) {
                                r(e)
                            }
                        }

                        function l(e) {
                            var t;
                            e.done ? i(e.value) : (t = e.value, t instanceof n ? t : new n((function(e) {
                                e(t)
                            }))).then(o, a)
                        }
                        l((s = s.apply(e, t || [])).next())
                    }))
                };
                class ut {
                    constructor(e, t, n) {
                        this.config = t, this.createPeerConnection(e, n), this.latencyCalculator = new ct
                    }
                    createPeerConnection(e, t) {
                        this.config.isFlagEnabled(Qe.iI.ForceTURN) && (e.iceTransportPolicy = "relay", a.Vy.Info("Forcing TURN usage by setting ICE Transport Policy in peer connection config.")), this.peerConnection = new RTCPeerConnection(e), this.peerConnection.onsignalingstatechange = e => this.handleSignalStateChange(e), this.peerConnection.oniceconnectionstatechange = e => this.handleIceConnectionStateChange(e), this.peerConnection.onicegatheringstatechange = e => this.handleIceGatheringStateChange(e), this.peerConnection.ontrack = e => this.handleOnTrack(e), this.peerConnection.onicecandidate = e => this.handleIceCandidate(e), this.peerConnection.ondatachannel = e => this.handleDataChannel(e), this.aggregatedStats = new st, this.preferredCodec = t, this.updateCodecSelection = !0
                    }
                    createOffer(e, t) {
                        return ht(this, void 0, void 0, (function*() {
                            a.Vy.Info("Create Offer");
                            const n = "localhost" === location.hostname || "127.0.0.1" === location.hostname,
                                s = "https:" === location.protocol;
                            let i = t.isFlagEnabled(Qe.iI.UseMic),
                                r = t.isFlagEnabled(Qe.iI.UseCamera);
                            !i && !r || n || s || (i = !1, r = !1, a.Vy.Error("Microphone and Webcam access in the browser will not work if you are not on HTTPS or localhost. Disabling mic and webcam access."), a.Vy.Error("For testing you can enable HTTP microphone access Chrome by visiting chrome://flags/ and enabling 'unsafely-treat-insecure-origin-as-secure'")), this.setupTransceiversAsync(i, r).finally((() => {
                                var t;
                                null === (t = this.peerConnection) || void 0 === t || t.createOffer(e).then((e => {
                                    var t;
                                    this.showTextOverlayConnecting(), e.sdp = this.mungeSDP(e.sdp, i), null === (t = this.peerConnection) || void 0 === t || t.setLocalDescription(e), this.onSendWebRTCOffer(e)
                                })).catch((() => {
                                    this.showTextOverlaySetupFailure()
                                }))
                            }))
                        }))
                    }
                    receiveOffer(e, t) {
                        return ht(this, void 0, void 0, (function*() {
                            var n;
                            a.Vy.Info("Receive Offer"), this.isFirefox() && (e.sdp = e.sdp.replace(/^a=extmap:\d+ http:\/\/www\.webrtc\.org\/experiments\/rtp-hdrext\/abs-capture-time\r\n/gm, "")), null === (n = this.peerConnection) || void 0 === n || n.setRemoteDescription(e).then((() => {
                                this.onSetRemoteDescription(e);
                                const n = "localhost" === location.hostname || "127.0.0.1" === location.hostname,
                                    s = "https:" === location.protocol;
                                let i = t.isFlagEnabled(Qe.iI.UseMic),
                                    r = t.isFlagEnabled(Qe.iI.UseCamera);
                                !i && !r || n || s || (i = !1, r = !1, a.Vy.Error("Microphone and Webcam access in the browser will not work if you are not on HTTPS or localhost. Disabling mic and webcam access."), a.Vy.Error("For testing you can enable HTTP microphone access Chrome by visiting chrome://flags/ and enabling 'unsafely-treat-insecure-origin-as-secure'")), this.config.setOptionSettingOptions(Qe.mY.PreferredCodec, this.fuzzyIntersectUEAndBrowserCodecs(e)), this.setupTransceiversAsync(i, r).finally((() => {
                                    var e;
                                    null === (e = this.peerConnection) || void 0 === e || e.createAnswer().then((e => {
                                        var t;
                                        return e.sdp = this.mungeSDP(e.sdp, i), null === (t = this.peerConnection) || void 0 === t ? void 0 : t.setLocalDescription(e)
                                    })).then((() => {
                                        var e;
                                        this.onSetLocalDescription(null === (e = this.peerConnection) || void 0 === e ? void 0 : e.currentLocalDescription)
                                    })).catch((e => {
                                        a.Vy.Error(`createAnswer() failed - ${e}`)
                                    }))
                                }))
                            }))
                        }))
                    }
                    receiveAnswer(e) {
                        var t;
                        null === (t = this.peerConnection) || void 0 === t || t.setRemoteDescription(e), this.config.setOptionSettingOptions(Qe.mY.PreferredCodec, this.fuzzyIntersectUEAndBrowserCodecs(e))
                    }
                    generateStats() {
                        this.peerConnection.getStats().then((e => {
                            this.aggregatedStats.processStats(e), this.onVideoStats(this.aggregatedStats);
                            const t = this.latencyCalculator.calculate(this.aggregatedStats, this.peerConnection.getReceivers());
                            // //analizar de stats ---- jose
                            // if (window.isCollectingTestStats){
                            //     console.log("-> Capturando metricas...")
                            //     e.forEach(report => {
                            //         if (report.type == "inbound-rtp" && report.kind === "video"){
                            //             console.log("REport completo: ", report);
                            //             const row = metricsHeaders.map (header => {
                            //                 if (header === "timestamp") return new Date().toISOString();
                            //                 return report[header] ?? 0;
                            //             });

                            //             metricsLog.push(row)
                            //         }
                            //     });
                            // }
                            if (window.isCollectingTestStats) {
                                console.log("-> Capturando métricas...");

                                e.forEach(report => {
                                    const timestamp = new Date().toISOString();

                                    if (report.type === "inbound-rtp" && report.kind === "video") {
                                        inboundVideoLog.push([
                                            timestamp,
                                            report.bytesReceived ?? 0,
                                            report.packetsLost ?? 0,
                                            report.jitter ?? 0,
                                            report.jitterBufferDelay ?? 0,
                                            report.jitterBufferEmittedCount ?? 0,
                                            report.framesPerSecond ?? 0,
                                            report.framesDropped ?? 0
                                        ]);
                                    }

                                    if (report.type === "remote-outbound-rtp" && report.kind === "video") {
                                        remoteOutboundVideoLog.push([
                                            timestamp,
                                            report.bytesSent ?? 0,
                                            report.packetsSent ?? 0
                                        ]);
                                    }

                                    if (report.type === "candidate-pair" && report.selected) {
                                        let rtt = report.currentRoundTripTime ?? 0;

                                        console.log("Candidate-pair report:", report);

                                        // if (prevSent !== null && prevRecv !== null) {
                                        //     const sentDiff = report.lastPacketSentTimestamp - prevSent;
                                        //     const recvDiff = report.lastPacketReceivedTimestamp - prevRecv;
                                        //     const diff = recvDiff - sentDiff;
                                            
                                        //     rtt = diff > 0 ? diff / 1000 : 0; // convertir a segundos
                                        //     console.log("El rtt es: ", rtt, "y viene de sentdiff", sentDiff, "y de recvDiff", recvDiff, "cuya resta es", diff);
                                        // }
                                        candidatePairLog.push([
                                            timestamp,
                                            report.bytesReceived ?? 0,
                                            report.bytesSent ?? 0,
                                            rtt,
                                            report.availableOutgoingBitrate ?? 0,
                                            report.availableIncomingBitrate ?? 0
                                        ]);

                                        prevSent = report.lastPacketSentTimestamp;
                                        prevRecv = report.lastPacketReceivedTimestamp;
                                    }

                                    if (report.type === "inbound-rtp" && report.kind === "audio") {
                                        inboundAudioLog.push([
                                            timestamp,
                                            report.bytesReceived ?? 0,
                                            report.packetsLost ?? 0,
                                            report.jitter ?? 0,
                                            report.jitterBufferDelay ?? 0,
                                            report.jitterBufferEmittedCount ?? 0,
                                            report.concealedSamples ?? 0
                                        ]);
                                    }
                                    if (report.type === "remote-inbound-rtp" && report.kind === "video") {
                                        remoteInboundVideoLog.push([timestamp, report.roundTripTime ?? 0, report.roundTripTimeMeasurements ?? 0, report.totalRoundTripTime ?? 0, report.currentRoundTripTime ?? 0]); // en segundos
                                    }
                                });
                            }

                            //analizar de stats ---- jose
                            if (this.onLatencyCalculated(t), this.updateCodecSelection && this.aggregatedStats.inboundVideoStats.codecId) {
                                const e = this.aggregatedStats.codecs.get(this.aggregatedStats.inboundVideoStats.codecId);
                                if (void 0 === e) return;
                                const t = e.mimeType.replace("video/", "");
                                let n = t;
                                e.sdpFmtpLine && "" !== e.sdpFmtpLine.trim() && (n = `${t} ${e.sdpFmtpLine.trim()}`);
                                const s = this.config.getSettingOption(Qe.mY.PreferredCodec).options;
                                if (s.includes(n)) return void this.config.setOptionSettingValue(Qe.mY.PreferredCodec, n);
                                const i = s.filter((e => -1 !== e.indexOf(t)));
                                if (i.length > 0) return void this.config.setOptionSettingValue(Qe.mY.PreferredCodec, i[0])
                            }
                        }))
                    }
                    close() {
                        this.peerConnection && (this.peerConnection.close(), this.peerConnection = null)
                    }
                    mungeSDP(e, t) {
                        let n = e.replace(/(a=fmtp:\d+ .*level-asymmetry-allowed=.*)\r\n/gm, "$1;x-google-start-bitrate=10000;x-google-max-bitrate=100000\r\n"),
                            s = "maxaveragebitrate=510000;";
                        return t && (s += "sprop-maxcapturerate=48000;"), s += this.config.isFlagEnabled(Qe.iI.ForceMonoAudio) ? "stereo=0;" : "stereo=1;", s += "useinbandfec=1", n = n.replace("useinbandfec=1", s), this.config.isFlagEnabled(Qe.iI.EnableCaptureTimeExt) && !this.isFirefox() && (n = ot.addVideoHeaderExtensionToSdp(n, "http://www.webrtc.org/experiments/rtp-hdrext/abs-capture-time")), n
                    }
                    isFirefox() {
                        return navigator.userAgent.indexOf("Firefox") > 0
                    }
                    handleOnIce(e) {
                        var t;
                        a.Vy.Info("peerconnection handleOnIce"), this.config.isFlagEnabled(Qe.iI.ForceTURN) && e.candidate.indexOf("relay") < 0 ? a.Vy.Info(`Dropping candidate because it was not TURN relay. | Type= ${e.type} | Protocol= ${e.protocol} | Address=${e.address} | Port=${e.port} |`) : null === (t = this.peerConnection) || void 0 === t || t.addIceCandidate(e)
                    }
                    handleSignalStateChange(e) {
                        a.Vy.Info("signaling state change: " + e)
                    }
                    handleIceConnectionStateChange(e) {
                        a.Vy.Info("ice connection state change: " + e), this.onIceConnectionStateChange(e)
                    }
                    handleIceGatheringStateChange(e) {
                        a.Vy.Info("ice gathering state change: " + JSON.stringify(e))
                    }
                    handleOnTrack(e) {
                        e.streams.length < 1 || "probator" == e.streams[0].id || ("video" == e.track.kind && (this.videoTrack = e.track), "audio" == e.track.kind && (this.audioTrack = e.track), this.onTrack(e))
                    }
                    handleIceCandidate(e) {
                        this.onPeerIceCandidate(e)
                    }
                    handleDataChannel(e) {
                        this.onDataChannel(e)
                    }
                    onTrack(e) {}
                    onIceConnectionStateChange(e) {}
                    onPeerIceCandidate(e) {}
                    onDataChannel(e) {}
                    fuzzyIntersectUEAndBrowserCodecs(e) {
                        const t = new Array,
                            n = this.parseAvailableCodecs(e),
                            s = this.config.getSettingOption(Qe.mY.PreferredCodec).options;
                        for (const e of n)
                            if (s.includes(e)) t.push(e);
                            else {
                                const n = e.split(" ")[0];
                                for (const e of s)
                                    if (e.includes(n)) {
                                        t.push(e);
                                        break
                                    }
                            } return t
                    }
                    setupTransceiversAsync(e, t) {
                        return ht(this, void 0, void 0, (function*() {
                            var n, s, i, r, o, a, l, c;
                            let d = !1;
                            for (const e of null !== (s = null === (n = this.peerConnection) || void 0 === n ? void 0 : n.getTransceivers()) && void 0 !== s ? s : [])
                                if (e && e.receiver && e.receiver.track && "video" === e.receiver.track.kind) {
                                    d = !0;
                                    break
                                } if (t ? yield this.setupVideoSender(d): d || null === (i = this.peerConnection) || void 0 === i || i.addTransceiver("video", {
                                    direction: "recvonly"
                                }), RTCRtpReceiver.getCapabilities && "" != this.preferredCodec)
                                for (const e of null !== (o = null === (r = this.peerConnection) || void 0 === r ? void 0 : r.getTransceivers()) && void 0 !== o ? o : [])
                                    if (e && e.receiver && e.receiver.track && "video" === e.receiver.track.kind && e.setCodecPreferences) {
                                        const t = this.preferredCodec.split(" "),
                                            n = {
                                                mimeType: "video/" + t[0],
                                                clockRate: 9e4,
                                                sdpFmtpLine: t[1] ? t[1] : ""
                                            },
                                            s = [n];
                                        RTCRtpReceiver.getCapabilities("video").codecs.forEach((e => {
                                            (e.mimeType != n.mimeType || (null == e ? void 0 : e.sdpFmtpLine) != (null == n ? void 0 : n.sdpFmtpLine)) && s.push(e)
                                        }));
                                        for (const e of s) void 0 !== (null == e ? void 0 : e.sdpFmtpLine) && "" !== e.sdpFmtpLine || delete e.sdpFmtpLine;
                                        e.setCodecPreferences(s)
                                    } let h = !1;
                            for (const e of null !== (l = null === (a = this.peerConnection) || void 0 === a ? void 0 : a.getTransceivers()) && void 0 !== l ? l : [])
                                if (e && e.receiver && e.receiver.track && "audio" === e.receiver.track.kind) {
                                    h = !0;
                                    break
                                } e ? yield this.setupAudioSender(h): h || null === (c = this.peerConnection) || void 0 === c || c.addTransceiver("audio", {
                                direction: "recvonly"
                            })
                        }))
                    }
                    setupVideoSender(e) {
                        return ht(this, void 0, void 0, (function*() {
                            var t, n, s, i;
                            const r = yield navigator.mediaDevices.getUserMedia({
                                video: !0
                            });
                            if (r)
                                if (e) {
                                    for (const e of null !== (n = null === (t = this.peerConnection) || void 0 === t ? void 0 : t.getTransceivers()) && void 0 !== n ? n : [])
                                        if (rt.canTransceiverReceiveVideo(e))
                                            for (const t of r.getTracks()) t.kind && "video" == t.kind && (e.sender.replaceTrack(t), e.direction = "sendrecv")
                                } else
                                    for (const e of r.getTracks()) e.kind && "video" == e.kind && (null === (s = this.peerConnection) || void 0 === s || s.addTransceiver(e, {
                                        direction: "sendrecv"
                                    }));
                            else e || null === (i = this.peerConnection) || void 0 === i || i.addTransceiver("video", {
                                direction: "recvonly"
                            })
                        }))
                    }
                    setupAudioSender(e) {
                        return ht(this, void 0, void 0, (function*() {
                            var t, n, s, i;
                            const r = {
                                    video: !1,
                                    audio: {
                                        autoGainControl: !1,
                                        channelCount: 1,
                                        echoCancellation: !1,
                                        latency: 0,
                                        noiseSuppression: !1,
                                        sampleRate: 48e3,
                                        sampleSize: 16,
                                        volume: 1
                                    }
                                },
                                o = yield navigator.mediaDevices.getUserMedia(r);
                            if (o)
                                if (e) {
                                    for (const e of null !== (n = null === (t = this.peerConnection) || void 0 === t ? void 0 : t.getTransceivers()) && void 0 !== n ? n : [])
                                        if (rt.canTransceiverReceiveAudio(e))
                                            for (const t of o.getTracks()) t.kind && "audio" == t.kind && (e.sender.replaceTrack(t), e.direction = "sendrecv")
                                } else
                                    for (const e of o.getTracks()) e.kind && "audio" == e.kind && (null === (s = this.peerConnection) || void 0 === s || s.addTransceiver(e, {
                                        direction: "sendrecv"
                                    }));
                            else e || null === (i = this.peerConnection) || void 0 === i || i.addTransceiver("audio", {
                                direction: "recvonly"
                            })
                        }))
                    }
                    onVideoStats(e) {}
                    onLatencyCalculated(e) {}
                    onSendWebRTCOffer(e) {}
                    onSetRemoteDescription(e) {}
                    onSetLocalDescription(e) {}
                    showTextOverlayConnecting() {}
                    showTextOverlaySetupFailure() {}
                    parseAvailableCodecs(e) {
                        if (!RTCRtpReceiver.getCapabilities) return ["Only available on Chrome"];
                        const t = [],
                            n = (0, it.splitSections)(e.sdp);
                        return n.shift(), n.forEach((e => {
                            const {
                                codecs: n
                            } = (0, it.parseRtpParameters)(e), s = /(VP\d|H26\d|AV1).*/;
                            n.forEach((e => {
                                const n = e.name + " " + Object.keys(e.parameters || {}).map((t => t + "=" + e.parameters[t])).join(";");
                                if (null !== s.exec(n)) {
                                    "VP9" == e.name && (e.parameters = {
                                        "profile-id": "0"
                                    });
                                    const n = e.name + " " + Object.keys(e.parameters || {}).map((t => t + "=" + e.parameters[t])).join(";");
                                    t.push(n)
                                }
                            }))
                        })), t
                    }
                }
                class mt {
                    constructor() {
                        this.PixelStreamingSettings = new pt, this.EncoderSettings = new gt, this.WebRTCSettings = new ft
                    }
                    ueCompatible() {
                        null != this.WebRTCSettings.MaxFPS && (this.WebRTCSettings.FPS = this.WebRTCSettings.MaxFPS)
                    }
                }
                class pt {}
                class gt {}
                class ft {}
                class yt {
                    constructor() {
                        this.ReceiptTimeMs = null, this.TransmissionTimeMs = null, this.PreCaptureTimeMs = null, this.PostCaptureTimeMs = null, this.PreEncodeTimeMs = null, this.PostEncodeTimeMs = null, this.EncodeMs = null, this.CaptureToSendMs = null, this.testStartTimeMs = 0, this.browserReceiptTimeMs = 0, this.latencyExcludingDecode = 0, this.testDuration = 0, this.networkLatency = 0, this.browserSendLatency = 0, this.frameDisplayDeltaTimeMs = 0, this.endToEndLatency = 0, this.encodeLatency = 0
                    }
                    setFrameDisplayDeltaTime(e) {
                        0 == this.frameDisplayDeltaTimeMs && (this.frameDisplayDeltaTimeMs = Math.round(e))
                    }
                    processFields() {
                        null != this.EncodeMs || null == this.PreEncodeTimeMs && null == this.PostEncodeTimeMs || (a.Vy.Info(`Setting Encode Ms \n ${this.PostEncodeTimeMs} \n ${this.PreEncodeTimeMs}`), this.EncodeMs = this.PostEncodeTimeMs - this.PreEncodeTimeMs), null != this.CaptureToSendMs || null == this.PreCaptureTimeMs && null == this.PostCaptureTimeMs || (a.Vy.Info(`Setting CaptureToSendMs Ms \n ${this.PostCaptureTimeMs} \n ${this.PreCaptureTimeMs}`), this.CaptureToSendMs = this.PostCaptureTimeMs - this.PreCaptureTimeMs)
                    }
                }
                class vt {
                    static setExtensionFromBytes(e, t) {
                        t.receiving || (t.mimetype = "", t.extension = "", t.receiving = !0, t.valid = !1, t.chunks = 0, t.data = [], t.timestampStart = (new Date).getTime(), a.Vy.Info("Received first chunk of file"));
                        const n = new TextDecoder("utf-16").decode(e.slice(1));
                        a.Vy.Info(n), t.extension = n
                    }
                    static setMimeTypeFromBytes(e, t) {
                        t.receiving || (t.mimetype = "", t.extension = "", t.receiving = !0, t.valid = !1, t.chunks = 0, t.data = [], t.timestampStart = (new Date).getTime(), a.Vy.Info("Received first chunk of file"));
                        const n = new TextDecoder("utf-16").decode(e.slice(1));
                        a.Vy.Info(n), t.mimetype = n
                    }
                    static setContentsFromBytes(e, t) {
                        if (!t.receiving) return;
                        t.chunks = Math.ceil(new DataView(e.slice(1, 5).buffer).getInt32(0, !0) / 16379);
                        const n = e.slice(5);
                        if (t.data.push(n), a.Vy.Info(`Received file chunk: ${t.data.length}/${t.chunks}`), t.data.length === t.chunks) {
                            t.receiving = !1, t.valid = !0, a.Vy.Info("Received complete file");
                            const e = (new Date).getTime() - t.timestampStart,
                                n = Math.round(16384 * t.chunks / e);
                            a.Vy.Info(`Average transfer bitrate: ${n}kb/s over ${e/1e3} seconds`);
                            const s = new Blob(t.data, {
                                    type: t.mimetype
                                }),
                                i = document.createElement("a");
                            i.setAttribute("href", URL.createObjectURL(s)), i.setAttribute("download", `transfer.${t.extension}`), document.body.append(i), i.remove()
                        } else t.data.length > t.chunks && (t.receiving = !1, a.Vy.Error(`Received bigger file than advertised: ${t.data.length}/${t.chunks}`))
                    }
                }
                class bt {
                    constructor() {
                        this.mimetype = "", this.extension = "", this.receiving = !1, this.chunks = 0, this.data = [], this.valid = !1
                    }
                }
                class St {}
                St.backSpace = 8, St.shift = 16, St.control = 17, St.alt = 18, St.rightShift = 253, St.rightControl = 254, St.rightAlt = 255;
                const Ct = Object.freeze({
                    Escape: 27,
                    Digit0: 48,
                    Digit1: 49,
                    Digit2: 50,
                    Digit3: 51,
                    Digit4: 52,
                    Digit5: 53,
                    Digit6: 54,
                    Digit7: 55,
                    Digit8: 56,
                    Digit9: 57,
                    Minus: 173,
                    Equal: 187,
                    Backspace: 8,
                    Tab: 9,
                    KeyQ: 81,
                    KeyW: 87,
                    KeyE: 69,
                    KeyR: 82,
                    KeyT: 84,
                    KeyY: 89,
                    KeyU: 85,
                    KeyI: 73,
                    KeyO: 79,
                    KeyP: 80,
                    BracketLeft: 219,
                    BracketRight: 221,
                    Enter: 13,
                    ControlLeft: 17,
                    KeyA: 65,
                    KeyS: 83,
                    KeyD: 68,
                    KeyF: 70,
                    KeyG: 71,
                    KeyH: 72,
                    KeyJ: 74,
                    KeyK: 75,
                    KeyL: 76,
                    Semicolon: 186,
                    Quote: 222,
                    Backquote: 192,
                    ShiftLeft: 16,
                    Backslash: 220,
                    KeyZ: 90,
                    KeyX: 88,
                    KeyC: 67,
                    KeyV: 86,
                    KeyB: 66,
                    KeyN: 78,
                    KeyM: 77,
                    Comma: 188,
                    Period: 190,
                    Slash: 191,
                    ShiftRight: 253,
                    AltLeft: 18,
                    Space: 32,
                    CapsLock: 20,
                    F1: 112,
                    F2: 113,
                    F3: 114,
                    F4: 115,
                    F5: 116,
                    F6: 117,
                    F7: 118,
                    F8: 119,
                    F9: 120,
                    F10: 121,
                    F11: 122,
                    F12: 123,
                    Pause: 19,
                    ScrollLock: 145,
                    NumpadDivide: 111,
                    NumpadMultiply: 106,
                    NumpadSubtract: 109,
                    NumpadAdd: 107,
                    NumpadDecimal: 110,
                    Numpad9: 105,
                    Numpad8: 104,
                    Numpad7: 103,
                    Numpad6: 102,
                    Numpad5: 101,
                    Numpad4: 100,
                    Numpad3: 99,
                    Numpad2: 98,
                    Numpad1: 97,
                    Numpad0: 96,
                    NumLock: 144,
                    ControlRight: 254,
                    AltRight: 255,
                    Home: 36,
                    End: 35,
                    ArrowUp: 38,
                    ArrowLeft: 37,
                    ArrowRight: 39,
                    ArrowDown: 40,
                    PageUp: 33,
                    PageDown: 34,
                    Insert: 45,
                    Delete: 46,
                    ContextMenu: 93
                });
                class wt {
                    constructor(e, t, n) {
                        this.streamMessageController = e, this.config = t, this.activeKeys = n, this.onKeyDownListener = this.handleOnKeyDown.bind(this), this.onKeyUpListener = this.handleOnKeyUp.bind(this), this.onKeyPressListener = this.handleOnKeyPress.bind(this)
                    }
                    register() {
                        document.addEventListener("keydown", this.onKeyDownListener), document.addEventListener("keyup", this.onKeyUpListener), document.addEventListener("keypress", this.onKeyPressListener)
                    }
                    unregister() {
                        document.removeEventListener("keydown", this.onKeyDownListener), document.removeEventListener("keyup", this.onKeyUpListener), document.removeEventListener("keypress", this.onKeyPressListener)
                    }
                    handleOnKeyDown(e) {
                        var t;
                        const n = this.getKeycode(e);
                        if (!n || 229 === n) return;
                        null === (t = this.streamMessageController.toStreamerHandlers.get("KeyDown")) || void 0 === t || t([this.getKeycode(e), e.repeat ? 1 : 0]);
                        this.activeKeys.getActiveKeys().push(n), n === St.backSpace && this.handleOnKeyPress(new KeyboardEvent("keypress", {
                            charCode: St.backSpace,
                            keyCode: St.backSpace
                        })), this.config.isFlagEnabled(Qe.iI.SuppressBrowserKeys) && this.isKeyCodeBrowserKey(n) && e.preventDefault()
                    }
                    handleOnKeyUp(e) {
                        var t;
                        const n = this.getKeycode(e);
                        if (!n) return;
                        null === (t = this.streamMessageController.toStreamerHandlers.get("KeyUp")) || void 0 === t || t([n]), this.config.isFlagEnabled(Qe.iI.SuppressBrowserKeys) && this.isKeyCodeBrowserKey(n) && e.preventDefault()
                    }
                    handleOnKeyPress(e) {
                        var t;
                        const n = this.getKeycode(e);
                        if (!n) return;
                        null === (t = this.streamMessageController.toStreamerHandlers.get("KeyPress")) || void 0 === t || t([n])
                    }
                    getKeycode(e) {
                        if (!("keyCode" in e)) {
                            const t = e;
                            return t.code in Ct ? Ct[t.code] : (a.Vy.Warning(`Keyboard code of ${t.code} is not supported in our mapping, ignoring this key.`), null)
                        }
                        return e.keyCode === St.shift && "ShiftRight" === e.code ? St.rightShift : e.keyCode === St.control && "ControlRight" === e.code ? St.rightControl : e.keyCode === St.alt && "AltRight" === e.code ? St.rightAlt : e.keyCode
                    }
                    isKeyCodeBrowserKey(e) {
                        return e >= 112 && e <= 123 || 9 === e
                    }
                    //movimiento personalizado --- jose
                    sendTestKeyInputs(durationMs) {
                        const keyCodes = [
                            Ct.KeyW, Ct.KeyA, Ct.KeyS, Ct.KeyD,
                            Ct.Space, Ct.ShiftLeft
                        ];
                        const vueltas = durationMs / 1000;

                        const handlerKeyDown = this.streamMessageController.toStreamerHandlers.get("KeyDown");
                        const handlerKeyUp = this.streamMessageController.toStreamerHandlers.get("KeyUp");

                        if (!handlerKeyDown || !handlerKeyUp) {
                            console.error("Handlers for KeyDown or KeyUp are not defined.");
                            return;
                        }

                        let index = 0;
                        let indexkeycodes = 0;

                        const interval = setInterval(() => {
                            if (index >= vueltas) {
                                clearInterval(interval);
                                return;
                            }
                            if(indexkeycodes >= keyCodes.length){
                                indexkeycodes = 0;
                            }

                            const code = keyCodes[indexkeycodes];
                            handlerKeyDown([code, 0]);
                            console.log("⬇️ KeyDown", code);

                            setTimeout(() => {
                                handlerKeyUp([code]);
                                console.log("⬆️ KeyUp", code);
                            }, 200);

                            index++;
                            indexkeycodes++;
                        }, 1000);
                    }

                    
                    //movimiento personalizado ---jose
                }
                class Et {}
                Et.mainButton = 0, Et.auxiliaryButton = 1, Et.secondaryButton = 2, Et.fourthButton = 3, Et.fifthButton = 4;
                class Tt {}
                Tt.primaryButton = 1, Tt.secondaryButton = 2, Tt.auxiliaryButton = 4, Tt.fourthButton = 8, Tt.fifthButton = 16;
                class Mt {
                    constructor(e, t, n, s) {
                        this.streamMessageController = e, this.coordinateConverter = n, this.videoPlayer = t, this.activeKeys = s, this.onEnterListener = this.onMouseEnter.bind(this), this.onLeaveListener = this.onMouseLeave.bind(this)
                    }
                    register() {
                        this.registerMouseEnterAndLeaveEvents()
                    }
                    unregister() {
                        this.unregisterMouseEnterAndLeaveEvents()
                    }
                    registerMouseEnterAndLeaveEvents() {
                        const e = this.videoPlayer.getVideoParentElement();
                        null == e || e.addEventListener("mouseenter", this.onEnterListener), null == e || e.addEventListener("mouseleave", this.onLeaveListener)
                    }
                    unregisterMouseEnterAndLeaveEvents() {
                        const e = this.videoPlayer.getVideoParentElement();
                        null == e || e.removeEventListener("mouseenter", this.onEnterListener), null == e || e.removeEventListener("mouseleave", this.onLeaveListener)
                    }
                    onMouseEnter(e) {
                        var t;
                        this.videoPlayer.isVideoReady() && (null === (t = this.streamMessageController.toStreamerHandlers.get("MouseEnter")) || void 0 === t || t(), this.pressMouseButtons(e.buttons, e.x, e.y))
                    }
                    onMouseLeave(e) {
                        var t;
                        this.videoPlayer.isVideoReady() && (null === (t = this.streamMessageController.toStreamerHandlers.get("MouseLeave")) || void 0 === t || t(), this.releaseMouseButtons(e.buttons, e.x, e.y))
                    }
                    releaseMouseButtons(e, t, n) {
                        const s = this.coordinateConverter.translateUnsigned(t, n);
                        e & Tt.primaryButton && this.sendMouseUp(Et.mainButton, s.x, s.y), e & Tt.secondaryButton && this.sendMouseUp(Et.secondaryButton, s.x, s.y), e & Tt.auxiliaryButton && this.sendMouseUp(Et.auxiliaryButton, s.x, s.y), e & Tt.fourthButton && this.sendMouseUp(Et.fourthButton, s.x, s.y), e & Tt.fifthButton && this.sendMouseUp(Et.fifthButton, s.x, s.y)
                    }
                    pressMouseButtons(e, t, n) {
                        if (!this.videoPlayer.isVideoReady()) return;
                        const s = this.coordinateConverter.translateUnsigned(t, n);
                        e & Tt.primaryButton && this.sendMouseDown(Et.mainButton, s.x, s.y), e & Tt.secondaryButton && this.sendMouseDown(Et.secondaryButton, s.x, s.y), e & Tt.auxiliaryButton && this.sendMouseDown(Et.auxiliaryButton, s.x, s.y), e & Tt.fourthButton && this.sendMouseDown(Et.fourthButton, s.x, s.y), e & Tt.fifthButton && this.sendMouseDown(Et.fifthButton, s.x, s.y)
                    }
                    sendMouseDown(e, t, n) {
                        var s;
                        null === (s = this.streamMessageController.toStreamerHandlers.get("MouseDown")) || void 0 === s || s([e, t, n])
                    }
                    sendMouseUp(e, t, n) {
                        var s;
                        const i = this.coordinateConverter.translateUnsigned(t, n);
                        null === (s = this.streamMessageController.toStreamerHandlers.get("MouseUp")) || void 0 === s || s([e, i.x, i.y])
                    }
                }
                class xt extends Mt {
                    constructor(e, t, n, s) {
                        super(e, t, n, s), this.videoElementParent = t.getVideoParentElement(), this.x = this.videoElementParent.getBoundingClientRect().width / 2, this.y = this.videoElementParent.getBoundingClientRect().height / 2, this.normalizedCoord = this.coordinateConverter.translateUnsigned(this.x, this.y), this.onRequestLockListener = this.onRequestLock.bind(this), this.onLockStateChangeListener = this.onLockStateChange.bind(this), this.onMouseUpListener = this.onMouseUp.bind(this), this.onMouseDownListener = this.onMouseDown.bind(this), this.onMouseDblClickListener = this.onMouseDblClick.bind(this), this.onMouseWheelListener = this.onMouseWheel.bind(this), this.onMouseMoveListener = this.onMouseMove.bind(this)
                    }
                    register() {
                        super.register(), this.videoElementParent.requestPointerLock = this.videoElementParent.requestPointerLock || this.videoElementParent.mozRequestPointerLock, document.exitPointerLock = document.exitPointerLock || document.mozExitPointerLock, this.videoElementParent.requestPointerLock && this.videoElementParent.addEventListener("click", this.onRequestLockListener), document.addEventListener("pointerlockchange", this.onLockStateChangeListener), document.addEventListener("mozpointerlockchange", this.onLockStateChangeListener), this.videoElementParent.addEventListener("mousedown", this.onMouseDownListener), this.videoElementParent.addEventListener("mouseup", this.onMouseUpListener), this.videoElementParent.addEventListener("wheel", this.onMouseWheelListener), this.videoElementParent.addEventListener("dblclick", this.onMouseDblClickListener)
                    }
                    unregister() {
                        const e = document.pointerLockElement || document.mozPointerLockElement;
                        document.exitPointerLock && e === this.videoElementParent && document.exitPointerLock(), this.videoElementParent.removeEventListener("click", this.onRequestLockListener), document.removeEventListener("pointerlockchange", this.onLockStateChangeListener), document.removeEventListener("mozpointerlockchange", this.onLockStateChangeListener), document.removeEventListener("mousemove", this.onMouseMoveListener), this.videoElementParent.removeEventListener("mousedown", this.onMouseDownListener), this.videoElementParent.removeEventListener("mouseup", this.onMouseUpListener), this.videoElementParent.removeEventListener("wheel", this.onMouseWheelListener), this.videoElementParent.removeEventListener("dblclick", this.onMouseDblClickListener), super.unregister()
                    }
                    onRequestLock() {
                        this.videoElementParent.requestPointerLock()
                    }
                    onLockStateChange() {
                        if ((document.pointerLockElement || document.mozPointerLockElement) === this.videoElementParent) a.Vy.Info("Pointer locked"), document.addEventListener("mousemove", this.onMouseMoveListener);
                        else {
                            a.Vy.Info("The pointer lock status is now unlocked"), document.removeEventListener("mousemove", this.onMouseMoveListener);
                            this.activeKeys.getActiveKeys().forEach((e => {
                                this.streamMessageController.toStreamerHandlers.get("KeyUp")([e])
                            }))
                        }
                    }
                    //testeo movimiento del mouse --- jose

                    sendTestMouseInputs(durationMs) {
                        const mouseClicks = durationMs / 500;
                        const moveStep = 10;
                        let clickCount = 0;

                        console.log("🖱️ Iniciando test de inputs de ratón...");

                        const mouseInterval = setInterval(() => {
                            if (!this.videoPlayer || !this.videoPlayer.isVideoReady()) {
                                console.warn("📺 Video no listo aún.");
                                return;
                            }

                            // Simular movimiento del ratón
                            this.x += moveStep;
                            this.y += moveStep;

                            this.normalizedCoord = this.coordinateConverter.translateUnsigned(this.x, this.y);
                            const s = this.coordinateConverter.translateSigned(moveStep, moveStep);




                            // MouseMove
                            const mouseMoveHandler = this.streamMessageController.toStreamerHandlers.get("MouseMove");
                            if (mouseMoveHandler) {
                                mouseMoveHandler([
                                    this.normalizedCoord.x,
                                    this.normalizedCoord.y,
                                    s.x,
                                    s.y
                                ]);
                            } else {
                                console.warn("⚠️ MouseMove handler no definido");
                            }

                            // MouseDown
                            const mouseDownHandler = this.streamMessageController.toStreamerHandlers.get("MouseDown");
                            if (mouseDownHandler) {
                                setTimeout(() => {mouseDownHandler([
                                    0,
                                    this.normalizedCoord.x,
                                    this.normalizedCoord.y
                                ]);
                                console.log("⬇️ MouseDown enviado");
                                }, 100);
                            }else {
                                console.warn("⚠️ MouseDown handler no definido");
                            }

                            // MouseUp
                            const mouseUpHandler = this.streamMessageController.toStreamerHandlers.get("MouseUp");
                            if (mouseUpHandler) {
                                mouseUpHandler([
                                    0,
                                    this.normalizedCoord.x,
                                    this.normalizedCoord.y
                                ]);
                            } else {
                                console.warn("⚠️ MouseUp handler no definido");
                            }

                            clickCount++;
                            if (clickCount >= mouseClicks) {
                                clearInterval(mouseInterval);
                                console.log("✅ Test de ratón completado.");
                            }
                        }, 1000);

                        // Seguridad: por si acaso
                        setTimeout(() => clearInterval(mouseInterval), durationMs);
                    }


                    //testeo movimiento del mosue --- jose
                    onMouseDown(e) {
                        this.videoPlayer.isVideoReady() && this.streamMessageController.toStreamerHandlers.get("MouseDown")([e.button, this.normalizedCoord.x, this.normalizedCoord.y])
                        console.log("cual es el botoncito....", e.button);
                    }
                    onMouseUp(e) {
                        this.videoPlayer.isVideoReady() && this.streamMessageController.toStreamerHandlers.get("MouseUp")([e.button, this.normalizedCoord.x, this.normalizedCoord.y])
                    }
                    onMouseMove(e) {
                        if (!this.videoPlayer.isVideoReady()) return;
                        const t = this.videoPlayer.getVideoParentElement().clientWidth,
                            n = this.videoPlayer.getVideoParentElement().clientHeight;
                        for (this.x += e.movementX, this.y += e.movementY; this.x > t;) this.x -= t;
                        for (; this.y > n;) this.y -= n;
                        for (; this.x < 0;) this.x += t;
                        for (; this.y < 0;) this.y += n;
                        this.normalizedCoord = this.coordinateConverter.translateUnsigned(this.x, this.y);
                        const s = this.coordinateConverter.translateSigned(e.movementX, e.movementY);
                        this.streamMessageController.toStreamerHandlers.get("MouseMove")([this.normalizedCoord.x, this.normalizedCoord.y, s.x, s.y])
                    }
                    onMouseWheel(e) {
                        this.videoPlayer.isVideoReady() && this.streamMessageController.toStreamerHandlers.get("MouseWheel")([e.wheelDelta, this.normalizedCoord.x, this.normalizedCoord.y])
                    }
                    onMouseDblClick(e) {
                        this.videoPlayer.isVideoReady() && this.streamMessageController.toStreamerHandlers.get("MouseDouble")([e.button, this.normalizedCoord.x, this.normalizedCoord.y])
                    }
                }
                class kt extends Mt {
                    constructor(e, t, n, s) {
                        super(e, t, n, s), this.videoElementParent = t.getVideoParentElement(), this.onMouseUpListener = this.onMouseUp.bind(this), this.onMouseDownListener = this.onMouseDown.bind(this), this.onMouseDblClickListener = this.onMouseDblClick.bind(this), this.onMouseWheelListener = this.onMouseWheel.bind(this), this.onMouseMoveListener = this.onMouseMove.bind(this), this.onContextMenuListener = this.onContextMenu.bind(this)
                    }
                    register() {
                        super.register(), this.videoElementParent.addEventListener("mousemove", this.onMouseMoveListener), this.videoElementParent.addEventListener("mousedown", this.onMouseDownListener), this.videoElementParent.addEventListener("mouseup", this.onMouseUpListener), this.videoElementParent.addEventListener("contextmenu", this.onContextMenuListener), this.videoElementParent.addEventListener("wheel", this.onMouseWheelListener), this.videoElementParent.addEventListener("dblclick", this.onMouseDblClickListener)
                    }
                    unregister() {
                        this.videoElementParent.removeEventListener("mousemove", this.onMouseMoveListener), this.videoElementParent.removeEventListener("mousedown", this.onMouseDownListener), this.videoElementParent.removeEventListener("mouseup", this.onMouseUpListener), this.videoElementParent.removeEventListener("contextmenu", this.onContextMenuListener), this.videoElementParent.removeEventListener("wheel", this.onMouseWheelListener), this.videoElementParent.removeEventListener("dblclick", this.onMouseDblClickListener), super.unregister()
                    }
                    onMouseDown(e) {
                        if (!this.videoPlayer.isVideoReady()) return;
                        const t = this.coordinateConverter.translateUnsigned(e.offsetX, e.offsetY);
                        this.streamMessageController.toStreamerHandlers.get("MouseDown")([e.button, t.x, t.y]), e.preventDefault()
                    }
                    onMouseUp(e) {
                        if (!this.videoPlayer.isVideoReady()) return;
                        const t = this.coordinateConverter.translateUnsigned(e.offsetX, e.offsetY);
                        this.streamMessageController.toStreamerHandlers.get("MouseUp")([e.button, t.x, t.y]), e.preventDefault()
                    }
                    onContextMenu(e) {
                        this.videoPlayer.isVideoReady() && e.preventDefault()
                    }
                    onMouseMove(e) {
                        if (!this.videoPlayer.isVideoReady()) return;
                        const t = this.coordinateConverter.translateUnsigned(e.offsetX, e.offsetY),
                            n = this.coordinateConverter.translateSigned(e.movementX, e.movementY);
                        this.streamMessageController.toStreamerHandlers.get("MouseMove")([t.x, t.y, n.x, n.y]), e.preventDefault()
                    }
                    onMouseWheel(e) {
                        if (!this.videoPlayer.isVideoReady()) return;
                        const t = this.coordinateConverter.translateUnsigned(e.offsetX, e.offsetY);
                        this.streamMessageController.toStreamerHandlers.get("MouseWheel")([e.wheelDelta, t.x, t.y]), e.preventDefault()
                    }
                    onMouseDblClick(e) {
                        if (!this.videoPlayer.isVideoReady()) return;
                        const t = this.coordinateConverter.translateUnsigned(e.offsetX, e.offsetY);
                        this.streamMessageController.toStreamerHandlers.get("MouseDouble")([e.button, t.x, t.y])
                    }
                }
                class Rt {
                    constructor(e, t, n) {
                        this.fingers = [9, 8, 7, 6, 5, 4, 3, 2, 1, 0], this.fingerIds = new Map, this.maxByteValue = 255, this.streamMessageController = e, this.videoPlayer = t, this.coordinateConverter = n, this.videoElementParent = t.getVideoElement(), this.onTouchStartListener = this.onTouchStart.bind(this), this.onTouchEndListener = this.onTouchEnd.bind(this), this.onTouchMoveListener = this.onTouchMove.bind(this)
                    }
                    register() {
                        this.videoElementParent.addEventListener("touchstart", this.onTouchStartListener), this.videoElementParent.addEventListener("touchend", this.onTouchEndListener), this.videoElementParent.addEventListener("touchmove", this.onTouchMoveListener)
                    }
                    unregister() {
                        this.videoElementParent.removeEventListener("touchstart", this.onTouchStartListener), this.videoElementParent.removeEventListener("touchend", this.onTouchEndListener), this.videoElementParent.removeEventListener("touchmove", this.onTouchMoveListener)
                    }
                    rememberTouch(e) {
                        const t = this.fingers.pop();
                        void 0 === t && a.Vy.Info("exhausted touch identifiers"), this.fingerIds.set(e.identifier, t)
                    }
                    forgetTouch(e) {
                        this.fingers.push(this.fingerIds.get(e.identifier)), this.fingers.sort((function(e, t) {
                            return t - e
                        })), this.fingerIds.delete(e.identifier)
                    }
                    onTouchStart(e) {
                        if (this.videoPlayer.isVideoReady()) {
                            for (let t = 0; t < e.changedTouches.length; t++) this.rememberTouch(e.changedTouches[t]);
                            this.emitTouchData("TouchStart", e.changedTouches), e.preventDefault()
                        }
                    }
                    onTouchEnd(e) {
                        if (this.videoPlayer.isVideoReady()) {
                            this.emitTouchData("TouchEnd", e.changedTouches);
                            for (let t = 0; t < e.changedTouches.length; t++) this.forgetTouch(e.changedTouches[t]);
                            e.preventDefault()
                        }
                    }
                    onTouchMove(e) {
                        this.videoPlayer.isVideoReady() && (this.emitTouchData("TouchMove", e.touches), e.preventDefault())
                    }
                    emitTouchData(e, t) {
                        if (!this.videoPlayer.isVideoReady()) return;
                        const n = this.videoPlayer.getVideoParentElement().getBoundingClientRect(),
                            s = this.streamMessageController.toStreamerHandlers;
                        for (let i = 0; i < t.length; i++) {
                            const r = 1,
                                o = t[i],
                                l = o.clientX - n.left,
                                c = o.clientY - n.top;
                            a.Vy.Info(`F${this.fingerIds.get(o.identifier)}=(${l}, ${c})`);
                            const d = this.coordinateConverter.translateUnsigned(l, c);
                            switch (e) {
                                case "TouchStart":
                                    s.get("TouchStart")([r, d.x, d.y, this.fingerIds.get(o.identifier), this.maxByteValue * (o.force > 0 ? o.force : 1), d.inRange ? 1 : 0]);
                                    break;
                                case "TouchEnd":
                                    s.get("TouchEnd")([r, d.x, d.y, this.fingerIds.get(o.identifier), this.maxByteValue * o.force, d.inRange ? 1 : 0]);
                                    break;
                                case "TouchMove":
                                    s.get("TouchMove")([r, d.x, d.y, this.fingerIds.get(o.identifier), this.maxByteValue * (o.force > 0 ? o.force : 1), d.inRange ? 1 : 0])
                            }
                        }
                    }
                }
                class Pt {
                    constructor(e, t, n) {
                        this.streamMessageController = e, this.videoPlayer = t, this.coordinateConverter = n, this.onTouchStartListener = this.onTouchStart.bind(this), this.onTouchEndListener = this.onTouchEnd.bind(this), this.onTouchMoveListener = this.onTouchMove.bind(this), this.videoElementParentClientRect = this.videoPlayer.getVideoParentElement().getBoundingClientRect()
                    }
                    register() {
                        document.addEventListener("touchstart", this.onTouchStartListener), document.addEventListener("touchend", this.onTouchEndListener), document.addEventListener("touchmove", this.onTouchMoveListener)
                    }
                    unregister() {
                        document.removeEventListener("touchstart", this.onTouchStartListener), document.removeEventListener("touchend", this.onTouchEndListener), document.removeEventListener("touchmove", this.onTouchMoveListener)
                    }
                    onTouchStart(e) {
                        if (this.videoPlayer.isVideoReady() && e.target === this.videoPlayer.getVideoElement()) {
                            if (null == this.fakeTouchFinger) {
                                const t = e.changedTouches[0];
                                this.fakeTouchFinger = {
                                    id: t.identifier,
                                    x: t.clientX - this.videoElementParentClientRect.left,
                                    y: t.clientY - this.videoElementParentClientRect.top
                                };
                                const n = this.videoPlayer.getVideoParentElement(),
                                    s = new MouseEvent("mouseenter", t);
                                n.dispatchEvent(s);
                                const i = this.coordinateConverter.translateUnsigned(this.fakeTouchFinger.x, this.fakeTouchFinger.y);
                                this.streamMessageController.toStreamerHandlers.get("MouseDown")([Et.mainButton, i.x, i.y])
                            }
                            e.preventDefault()
                        }
                    }
                    onTouchEnd(e) {
                        if (!this.videoPlayer.isVideoReady() || null == this.fakeTouchFinger) return;
                        const t = this.videoPlayer.getVideoParentElement(),
                            n = this.streamMessageController.toStreamerHandlers;
                        for (let s = 0; s < e.changedTouches.length; s++) {
                            const i = e.changedTouches[s];
                            if (i.identifier === this.fakeTouchFinger.id) {
                                const e = i.clientX - this.videoElementParentClientRect.left,
                                    s = i.clientY - this.videoElementParentClientRect.top,
                                    r = this.coordinateConverter.translateUnsigned(e, s);
                                n.get("MouseUp")([Et.mainButton, r.x, r.y]);
                                const o = new MouseEvent("mouseleave", i);
                                t.dispatchEvent(o), this.fakeTouchFinger = null;
                                break
                            }
                        }
                        e.preventDefault()
                    }
                    onTouchMove(e) {
                        if (!this.videoPlayer.isVideoReady() || null == this.fakeTouchFinger) return;
                        const t = this.streamMessageController.toStreamerHandlers;
                        for (let n = 0; n < e.touches.length; n++) {
                            const s = e.touches[n];
                            if (s.identifier === this.fakeTouchFinger.id) {
                                const e = s.clientX - this.videoElementParentClientRect.left,
                                    n = s.clientY - this.videoElementParentClientRect.top,
                                    i = this.coordinateConverter.translateUnsigned(e, n),
                                    r = this.coordinateConverter.translateSigned(e - this.fakeTouchFinger.x, n - this.fakeTouchFinger.y);
                                t.get("MouseMove")([i.x, i.y, r.x, r.y]), this.fakeTouchFinger.x = e, this.fakeTouchFinger.y = n;
                                break
                            }
                        }
                        e.preventDefault()
                    }
                }
                var It, Lt, Ot = n(945);
                ! function(e) {
                    e[e.RightClusterBottomButton = 0] = "RightClusterBottomButton", e[e.RightClusterRightButton = 1] = "RightClusterRightButton", e[e.RightClusterLeftButton = 2] = "RightClusterLeftButton", e[e.RightClusterTopButton = 3] = "RightClusterTopButton", e[e.LeftShoulder = 4] = "LeftShoulder", e[e.RightShoulder = 5] = "RightShoulder", e[e.LeftTrigger = 6] = "LeftTrigger", e[e.RightTrigger = 7] = "RightTrigger", e[e.SelectOrBack = 8] = "SelectOrBack", e[e.StartOrForward = 9] = "StartOrForward", e[e.LeftAnalogPress = 10] = "LeftAnalogPress", e[e.RightAnalogPress = 11] = "RightAnalogPress", e[e.LeftClusterTopButton = 12] = "LeftClusterTopButton", e[e.LeftClusterBottomButton = 13] = "LeftClusterBottomButton", e[e.LeftClusterLeftButton = 14] = "LeftClusterLeftButton", e[e.LeftClusterRightButton = 15] = "LeftClusterRightButton", e[e.CentreButton = 16] = "CentreButton", e[e.LeftStickHorizontal = 0] = "LeftStickHorizontal", e[e.LeftStickVertical = 1] = "LeftStickVertical", e[e.RightStickHorizontal = 2] = "RightStickHorizontal", e[e.RightStickVertical = 3] = "RightStickVertical"
                }(It || (It = {}));
                class Ft {
                    constructor(e) {
                        this.streamMessageController = e, this.onGamepadConnectedListener = this.onGamepadConnected.bind(this), this.onGamepadDisconnectedListener = this.onGamepadDisconnected.bind(this), this.beforeUnloadListener = this.onBeforeUnload.bind(this), this.requestAnimationFrame = (window.mozRequestAnimationFrame || window.webkitRequestAnimationFrame || window.requestAnimationFrame).bind(window)
                    }
                    register() {
                        window.addEventListener("beforeunload", this.beforeUnloadListener);
                        const e = window;
                        if ("GamepadEvent" in e ? (window.addEventListener("gamepadconnected", this.onGamepadConnectedListener), window.addEventListener("gamepaddisconnected", this.onGamepadDisconnectedListener)) : "WebKitGamepadEvent" in e && (window.addEventListener("webkitgamepadconnected", this.onGamepadConnectedListener), window.addEventListener("webkitgamepaddisconnected", this.onGamepadDisconnectedListener)), this.controllers = [], navigator.getGamepads)
                            for (const e of navigator.getGamepads()) e && this.onGamepadConnected(new GamepadEvent("gamepadconnected", {
                                gamepad: e
                            }))
                    }
                    unregister() {
                        window.removeEventListener("gamepadconnected", this.onGamepadConnectedListener), window.removeEventListener("gamepaddisconnected", this.onGamepadDisconnectedListener), window.removeEventListener("webkitgamepadconnected", this.onGamepadConnectedListener), window.removeEventListener("webkitgamepaddisconnected", this.onGamepadDisconnectedListener);
                        for (const e of this.controllers) e && void 0 !== e.id && this.streamMessageController.toStreamerHandlers.get("GamepadDisconnected")([e.id]);
                        this.controllers = []
                    }
                    onGamepadResponseReceived(e) {
                        for (const t of this.controllers)
                            if (t && void 0 === t.id) {
                                t.id = e;
                                break
                            }
                    }
                    onGamepadConnected(e) {
                        const t = e.gamepad,
                            n = {
                                currentState: (0, Ot.L)(t),
                                prevState: (0, Ot.L)(t),
                                id: void 0
                            };
                        this.controllers[t.index] = n, window.requestAnimationFrame((() => this.updateStatus())), this.streamMessageController.toStreamerHandlers.get("GamepadConnected")()
                    }
                    onGamepadDisconnected(e) {
                        const t = e.gamepad,
                            n = this.controllers[t.index];
                        delete this.controllers[t.index], this.controllers = this.controllers.filter((e => void 0 !== e)), void 0 !== n.id && this.streamMessageController.toStreamerHandlers.get("GamepadDisconnected")([n.id])
                    }
                    scanGamepads() {
                        const e = navigator.getGamepads ? navigator.getGamepads() : navigator.webkitGetGamepads ? navigator.webkitGetGamepads() : [];
                        for (let t = 0; t < e.length; t++) e[t] && void 0 !== this.controllers[e[t].index] && (this.controllers[e[t].index].currentState = e[t])
                    }
                    updateStatus() {
                        this.scanGamepads();
                        const e = this.streamMessageController.toStreamerHandlers;
                        for (const t of this.controllers) {
                            if (!t) continue;
                            const n = void 0 === t.id ? this.controllers.indexOf(t) : t.id,
                                s = t.currentState;
                            for (let s = 0; s < t.currentState.buttons.length; s++) {
                                const i = t.currentState.buttons[s],
                                    r = t.prevState.buttons[s];
                                i.pressed ? s == It.LeftTrigger ? e.get("GamepadAnalog")([n, 5, i.value]) : s == It.RightTrigger ? e.get("GamepadAnalog")([n, 6, i.value]) : e.get("GamepadButtonPressed")([n, s, r.pressed ? 1 : 0]) : !i.pressed && r.pressed && (s == It.LeftTrigger ? e.get("GamepadAnalog")([n, 5, 0]) : s == It.RightTrigger ? e.get("GamepadAnalog")([n, 6, 0]) : e.get("GamepadButtonReleased")([n, s, 0]))
                            }
                            for (let t = 0; t < s.axes.length; t += 2) {
                                const i = parseFloat(s.axes[t].toFixed(4)),
                                    r = -parseFloat(s.axes[t + 1].toFixed(4));
                                e.get("GamepadAnalog")([n, t + 1, i]), e.get("GamepadAnalog")([n, t + 2, r])
                            }
                            const i = this.controllers.indexOf(t);
                            this.controllers[i].prevState = (0, Ot.L)(s)
                        }
                        this.controllers.length > 0 && this.requestAnimationFrame((() => this.updateStatus()))
                    }
                    onBeforeUnload(e) {
                        for (const e of this.controllers) e && void 0 !== e.id && this.streamMessageController.toStreamerHandlers.get("GamepadDisconnected")([e.id])
                    }
                }
                class Dt {
                    constructor(e, t, n) {
                        this.activeKeys = new At, this.toStreamerMessagesProvider = e, this.videoElementProvider = t, this.coordinateConverter = n
                    }
                    registerKeyBoard(e) {
                        a.Vy.Info("Register Keyboard Events");
                        const t = new wt(this.toStreamerMessagesProvider, e, this.activeKeys);
                        return t.register(), t
                    }
                    registerMouse(e) {
                        let t;
                        return a.Vy.Info("Register Mouse Events"), t = e == Qe.Bs.HoveringMouse ? new kt(this.toStreamerMessagesProvider, this.videoElementProvider, this.coordinateConverter, this.activeKeys) : new xt(this.toStreamerMessagesProvider, this.videoElementProvider, this.coordinateConverter, this.activeKeys), t.register(), t
                    }
                    registerTouch(e) {
                        let t;
                        return a.Vy.Info("Registering Touch"), t = e ? new Pt(this.toStreamerMessagesProvider, this.videoElementProvider, this.coordinateConverter) : new Rt(this.toStreamerMessagesProvider, this.videoElementProvider, this.coordinateConverter), t.register(), t
                    }
                    registerGamePad() {
                        a.Vy.Info("Register Game Pad");
                        const e = new Ft(this.toStreamerMessagesProvider);
                        return e.register(), e
                    }
                }
                class At {
                    constructor() {
                        this.activeKeys = [], this.activeKeys = []
                    }
                    getActiveKeys() {
                        return this.activeKeys
                    }
                }
                class _t {
                    constructor(e, t) {
                        this.lastTimeResized = (new Date).getTime(), this.videoElement = document.createElement("video"), this.config = t, this.videoElement.id = "streamingVideo", this.videoElement.disablePictureInPicture = !0, this.videoElement.playsInline = !0, this.videoElement.style.width = "100%", this.videoElement.style.height = "100%", this.videoElement.style.position = "absolute", this.videoElement.style.pointerEvents = "all", e.appendChild(this.videoElement), this.onResizePlayerCallback = () => {
                            console.log("Resolution changed, restyling player, did you forget to override this function?")
                        }, this.onMatchViewportResolutionCallback = () => {
                            console.log("Resolution changed and match viewport resolution is turned on, did you forget to override this function?")
                        }, this.videoElement.onclick = () => {
                            null != this.audioElement && this.audioElement.paused && this.audioElement.play(), this.videoElement.paused && this.videoElement.play()
                        }, this.videoElement.onloadedmetadata = () => {
                            this.onVideoInitialized()
                        }, window.addEventListener("resize", (() => this.resizePlayerStyle()), !0), window.addEventListener("orientationchange", (() => this.onOrientationChange()))
                    }
                    destroy() {
                        this.videoElement.src = "", this.videoElement.srcObject = null, this.videoElement.remove(), this.audioElement && (this.audioElement.src = "", this.audioElement.srcObject = null, this.audioElement.remove())
                    }
                    setAudioElement(e) {
                        this.audioElement = e
                    }
                    play() {
                        return this.videoElement.muted = this.config.isFlagEnabled(Qe.iI.StartVideoMuted), this.videoElement.autoplay = this.config.isFlagEnabled(Qe.iI.AutoPlayVideo), this.videoElement.play()
                    }
                    isPaused() {
                        return this.videoElement.paused
                    }
                    isVideoReady() {
                        return void 0 !== this.videoElement.readyState && this.videoElement.readyState > 0
                    }
                    hasVideoSource() {
                        return void 0 !== this.videoElement.srcObject && null !== this.videoElement.srcObject
                    }
                    getVideoElement() {
                        return this.videoElement
                    }
                    getVideoParentElement() {
                        var e;
                        return null !== (e = this.videoElement.parentElement) && void 0 !== e ? e : void 0
                    }
                    setVideoEnabled(e) {
                        this.videoElement.srcObject.getTracks().forEach((t => t.enabled = e))
                    }
                    onVideoInitialized() {}
                    onOrientationChange() {
                        clearTimeout(this.orientationChangeTimeout), this.orientationChangeTimeout = window.setTimeout((() => {
                            this.resizePlayerStyle()
                        }), 500)
                    }
                    resizePlayerStyle() {
                        const e = this.getVideoParentElement();
                        e && (this.updateVideoStreamSize(), e.classList.contains("fixed-size") || this.resizePlayerStyleToFillParentElement(), this.onResizePlayerCallback())
                    }
                    resizePlayerStyleToFillParentElement() {
                        this.getVideoParentElement().setAttribute("style", "top: 0px; left: 0px; width: 100%; height: 100%; cursor: default;")
                    }
                    updateVideoStreamSize() {
                        if (!this.config.isFlagEnabled(Qe.iI.MatchViewportResolution)) return;
                        if ((new Date).getTime() - this.lastTimeResized > 300) {
                            const e = this.getVideoParentElement();
                            if (!e) return;
                            this.onMatchViewportResolutionCallback(e.clientWidth, e.clientHeight), this.lastTimeResized = (new Date).getTime()
                        } else a.Vy.Info("Resizing too often - skipping"), clearTimeout(this.resizeTimeoutHandle), this.resizeTimeoutHandle = window.setTimeout((() => this.updateVideoStreamSize()), 100)
                    }
                }
                class Vt {
                    constructor() {
                        this.toStreamerHandlers = new Map, this.fromStreamerHandlers = new Map, this.toStreamerMessages = new Map, this.fromStreamerMessages = new Map
                    }
                    populateDefaultProtocol() {
                        this.toStreamerMessages.set("IFrameRequest", {
                            id: 0,
                            structure: []
                        }), this.toStreamerMessages.set("RequestQualityControl", {
                            id: 1,
                            structure: []
                        }), this.toStreamerMessages.set("FpsRequest", {
                            id: 2,
                            structure: []
                        }), this.toStreamerMessages.set("AverageBitrateRequest", {
                            id: 3,
                            structure: []
                        }), this.toStreamerMessages.set("StartStreaming", {
                            id: 4,
                            structure: []
                        }), this.toStreamerMessages.set("StopStreaming", {
                            id: 5,
                            structure: []
                        }), this.toStreamerMessages.set("LatencyTest", {
                            id: 6,
                            structure: ["string"]
                        }), this.toStreamerMessages.set("RequestInitialSettings", {
                            id: 7,
                            structure: []
                        }), this.toStreamerMessages.set("TestEcho", {
                            id: 8,
                            structure: []
                        }), this.toStreamerMessages.set("DataChannelLatencyTest", {
                            id: 9,
                            structure: []
                        }), this.toStreamerMessages.set("UIInteraction", {
                            id: 50,
                            structure: ["string"]
                        }), this.toStreamerMessages.set("Command", {
                            id: 51,
                            structure: ["string"]
                        }), this.toStreamerMessages.set("TextboxEntry", {
                            id: 52,
                            structure: ["string"]
                        }), this.toStreamerMessages.set("KeyDown", {
                            id: 60,
                            structure: ["uint8", "uint8"]
                        }), this.toStreamerMessages.set("KeyUp", {
                            id: 61,
                            structure: ["uint8"]
                        }), this.toStreamerMessages.set("KeyPress", {
                            id: 62,
                            structure: ["uint16"]
                        }), this.toStreamerMessages.set("MouseEnter", {
                            id: 70,
                            structure: []
                        }), this.toStreamerMessages.set("MouseLeave", {
                            id: 71,
                            structure: []
                        }), this.toStreamerMessages.set("MouseDown", {
                            id: 72,
                            structure: ["uint8", "uint16", "uint16"]
                        }), this.toStreamerMessages.set("MouseUp", {
                            id: 73,
                            structure: ["uint8", "uint16", "uint16"]
                        }), this.toStreamerMessages.set("MouseMove", {
                            id: 74,
                            structure: ["uint16", "uint16", "int16", "int16"]
                        }), this.toStreamerMessages.set("MouseWheel", {
                            id: 75,
                            structure: ["int16", "uint16", "uint16"]
                        }), this.toStreamerMessages.set("MouseDouble", {
                            id: 76,
                            structure: ["uint8", "uint16", "uint16"]
                        }), this.toStreamerMessages.set("TouchStart", {
                            id: 80,
                            structure: ["uint8", "uint16", "uint16", "uint8", "uint8", "uint8"]
                        }), this.toStreamerMessages.set("TouchEnd", {
                            id: 81,
                            structure: ["uint8", "uint16", "uint16", "uint8", "uint8", "uint8"]
                        }), this.toStreamerMessages.set("TouchMove", {
                            id: 82,
                            structure: ["uint8", "uint16", "uint16", "uint8", "uint8", "uint8"]
                        }), this.toStreamerMessages.set("GamepadConnected", {
                            id: 93,
                            structure: []
                        }), this.toStreamerMessages.set("GamepadButtonPressed", {
                            id: 90,
                            structure: ["uint8", "uint8", "uint8"]
                        }), this.toStreamerMessages.set("GamepadButtonReleased", {
                            id: 91,
                            structure: ["uint8", "uint8", "uint8"]
                        }), this.toStreamerMessages.set("GamepadAnalog", {
                            id: 92,
                            structure: ["uint8", "uint8", "double"]
                        }), this.toStreamerMessages.set("GamepadDisconnected", {
                            id: 94,
                            structure: ["uint8"]
                        }), this.fromStreamerMessages.set(0, "QualityControlOwnership"), this.fromStreamerMessages.set(1, "Response"), this.fromStreamerMessages.set(2, "Command"), this.fromStreamerMessages.set(3, "FreezeFrame"), this.fromStreamerMessages.set(4, "UnfreezeFrame"), this.fromStreamerMessages.set(5, "VideoEncoderAvgQP"), this.fromStreamerMessages.set(6, "LatencyTest"), this.fromStreamerMessages.set(7, "InitialSettings"), this.fromStreamerMessages.set(8, "FileExtension"), this.fromStreamerMessages.set(9, "FileMimeType"), this.fromStreamerMessages.set(10, "FileContents"), this.fromStreamerMessages.set(11, "TestEcho"), this.fromStreamerMessages.set(12, "InputControlOwnership"), this.fromStreamerMessages.set(13, "GamepadResponse"), this.fromStreamerMessages.set(14, "DataChannelLatencyTest"), this.fromStreamerMessages.set(255, "Protocol")
                    }
                    registerMessageHandler(e, t, n) {
                        switch (e) {
                            case Lt.ToStreamer:
                                this.toStreamerHandlers.set(t, n);
                                break;
                            case Lt.FromStreamer:
                                this.fromStreamerHandlers.set(t, n);
                                break;
                            default:
                                a.Vy.Info(`Unknown message direction ${e}`)
                        }
                    }
                }! function(e) {
                    e[e.ToStreamer = 0] = "ToStreamer", e[e.FromStreamer = 1] = "FromStreamer"
                }(Lt || (Lt = {}));
                class Nt {
                    constructor() {
                        this.responseEventListeners = new Map
                    }
                    addResponseEventListener(e, t) {
                        this.responseEventListeners.set(e, t)
                    }
                    removeResponseEventListener(e) {
                        this.responseEventListeners.delete(e)
                    }
                    onResponse(e) {
                        a.Vy.Info("DataChannelReceiveMessageType.Response");
                        const t = new TextDecoder("utf-16").decode(e.slice(1));
                        a.Vy.Info(t), this.responseEventListeners.forEach((e => {
                            e(t)
                        }))
                    }
                }
                class Ut {
                    constructor(e, t) {
                        this.dataChannelSender = e, this.toStreamerMessagesMapProvider = t
                    }
                    sendMessageToStreamer(e, t) {
                        void 0 === t && (t = []);
                        const n = this.toStreamerMessagesMapProvider.toStreamerMessages.get(e);
                        if (void 0 === n) return void a.Vy.Error(`Attempted to send a message to the streamer with message type: ${e}, but the frontend hasn't been configured to send such a message. Check you've added the message type in your cpp`);
                        if (n.structure && t && n.structure.length !== t.length) return void a.Vy.Error(`Provided message data doesn't match expected layout. Expected [ ${n.structure.map((e=>{switch(e){case"uint8":case"uint16":case"int16":case"float":case"double":default:return"number";case"string":return"string"}})).toString()} ] but received [ ${t.map((e=>typeof e)).toString()} ]`);
                        let s = 0;
                        const i = new TextEncoder;
                        t.forEach(((e, t) => {
                            switch (n.structure[t]) {
                                case "uint8":
                                    s += 1;
                                    break;
                                case "uint16":
                                case "int16":
                                    s += 2;
                                    break;
                                case "float":
                                    s += 4;
                                    break;
                                case "double":
                                    s += 8;
                                    break;
                                case "string":
                                    s += 2, s += 2 * i.encode(e).length
                            }
                        }));
                        const r = new DataView(new ArrayBuffer(s + 1));
                        r.setUint8(0, n.id);
                        let o = 1;
                        t.forEach(((e, t) => {
                            switch (n.structure[t]) {
                                case "uint8":
                                    r.setUint8(o, e), o += 1;
                                    break;
                                case "uint16":
                                    r.setUint16(o, e, !0), o += 2;
                                    break;
                                case "int16":
                                    r.setInt16(o, e, !0), o += 2;
                                    break;
                                case "float":
                                    r.setFloat32(o, e, !0), o += 4;
                                    break;
                                case "double":
                                    r.setFloat64(o, e, !0), o += 8;
                                    break;
                                case "string":
                                    r.setUint16(o, e.length, !0), o += 2;
                                    for (let t = 0; t < e.length; t++) r.setUint16(o, e.charCodeAt(t), !0), o += 2
                            }
                        })), this.dataChannelSender.canSend() ? this.dataChannelSender.sendData(r.buffer) : a.Vy.Info(`Data channel cannot send yet, skipping sending message: ${e} - ${new Uint8Array(r.buffer)}`)
                    }
                }
                class Bt {
                    constructor(e) {
                        this.sendMessageController = e
                    }
                    SendRequestQualityControl() {
                        this.sendMessageController.sendMessageToStreamer("RequestQualityControl")
                    }
                    SendMaxFpsRequest() {
                        this.sendMessageController.sendMessageToStreamer("FpsRequest")
                    }
                    SendAverageBitrateRequest() {
                        this.sendMessageController.sendMessageToStreamer("AverageBitrateRequest")
                    }
                    SendStartStreaming() {
                        this.sendMessageController.sendMessageToStreamer("StartStreaming")
                    }
                    SendStopStreaming() {
                        this.sendMessageController.sendMessageToStreamer("StopStreaming")
                    }
                    SendRequestInitialSettings() {
                        this.sendMessageController.sendMessageToStreamer("RequestInitialSettings")
                    }
                }
                class Wt {
                    constructor(e) {
                        this.dataChannelProvider = e
                    }
                    canSend() {
                        return void 0 !== this.dataChannelProvider.getDataChannelInstance().dataChannel && "open" == this.dataChannelProvider.getDataChannelInstance().dataChannel.readyState
                    }
                    sendData(e) {
                        const t = this.dataChannelProvider.getDataChannelInstance();
                        "open" == t.dataChannel.readyState ? (t.dataChannel.send(e), a.Vy.Info(`Message Sent: ${new Uint8Array(e)}`), this.resetAfkWarningTimerOnDataSend()) : a.Vy.Error(`Message Failed: ${new Uint8Array(e)}`)
                    }
                    resetAfkWarningTimerOnDataSend() {}
                }
                class zt {
                    reconfigure(e, t) {
                        const n = e.height / e.width,
                            s = t.height / t.width;
                        this.playerIsLarger = n > s, this.playerSize = e, this.ratio = this.playerIsLarger ? n / s : s / n
                    }
                    translateUnsigned(e, t) {
                        const n = this.playerIsLarger ? e / this.playerSize.width : this.ratio * (e / this.playerSize.width - .5) + .5,
                            s = this.playerIsLarger ? this.ratio * (t / this.playerSize.height - .5) + .5 : t / this.playerSize.height;
                        return n < 0 || n > 1 || s < 0 || s > 1 ? {
                            inRange: !1,
                            x: 65535,
                            y: 65535
                        } : {
                            inRange: !0,
                            x: 65536 * n,
                            y: 65536 * s
                        }
                    }
                    translateSigned(e, t) {
                        return {
                            x: 32767 * (this.playerIsLarger ? e / (.5 * this.playerSize.width) : this.ratio * e / (.5 * this.playerSize.width)),
                            y: 32767 * (this.playerIsLarger ? this.ratio * t / (.5 * this.playerSize.height) : t / (.5 * this.playerSize.height))
                        }
                    }
                    untranslateUnsigned(e, t) {
                        const n = this.playerIsLarger ? e / 65536 : (e / 65536 - .5) / this.ratio + .5,
                            s = this.playerIsLarger ? (t / 65536 - .5) / this.ratio + .5 : t / 65536;
                        return {
                            x: n * this.playerSize.width,
                            y: s * this.playerSize.height
                        }
                    }
                }
                class Ht {
                    constructor(e) {
                        this._urlParams = {};
                        const t = new URLSearchParams(e);
                        for (const [e, n] of t) this._urlParams[e.toLowerCase()] = n
                    }
                    has(e) {
                        return e.toLowerCase() in this._urlParams
                    }
                    get(e) {
                        return this.has(e) ? this._urlParams[e.toLowerCase()] : null
                    }
                }
                var jt = n(171);
                class Qt {
                    constructor(e, t) {
                        this.shouldShowPlayOverlay = !0, this.autoJoinTimer = void 0, this.config = e, this.pixelStreaming = t, this.responseController = new Nt, this.file = new bt, this.sdpConstraints = {
                            offerToReceiveAudio: !0,
                            offerToReceiveVideo: !0
                        }, this.afkController = new Ke(this.config, this.pixelStreaming, this.onAfkTriggered.bind(this)), this.afkController.onAFKTimedOutCallback = () => {
                            this.closeSignalingServer("You have been disconnected due to inactivity.", !1)
                        }, this.freezeFrameController = new je(this.pixelStreaming.videoElementParent), this.videoPlayer = new _t(this.pixelStreaming.videoElementParent, this.config), this.videoPlayer.onVideoInitialized = () => this.handleVideoInitialized(), this.videoPlayer.onMatchViewportResolutionCallback = (e, t) => {
                            const n = {
                                "Resolution.Width": e,
                                "Resolution.Height": t
                            };
                            this.streamMessageController.toStreamerHandlers.get("Command")([JSON.stringify(n)])
                        }, this.videoPlayer.onResizePlayerCallback = () => {
                            this.setUpMouseAndFreezeFrame()
                        }, this.streamController = new ze(this.videoPlayer), this.coordinateConverter = new zt, this.sendrecvDataChannelController = new Ge, this.recvDataChannelController = new Ge, this.registerDataChannelEventEmitters(this.sendrecvDataChannelController), this.registerDataChannelEventEmitters(this.recvDataChannelController), this.dataChannelSender = new Wt(this.sendrecvDataChannelController), this.dataChannelSender.resetAfkWarningTimerOnDataSend = () => this.afkController.resetAfkWarningTimer(), this.streamMessageController = new Vt, this.transport = new d(e.webSocketProtocols), this.protocol = new h(this.transport), this.protocol.addListener(ce.typeName, (e => this.handleOnConfigMessage(e))), this.protocol.addListener(xe.typeName, (e => this.handlePingMessage(e))), this.protocol.addListener(ge.typeName, (e => this.handleStreamerListMessage(e))), this.protocol.addListener(ve.typeName, (e => this.handleSubscribeFailedMessage(e))), this.protocol.addListener(me.typeName, (e => this.handleStreamerIDChangedMessage(e))), this.protocol.addListener(_e.typeName, (e => {
                            const t = e;
                            this.pixelStreaming._onPlayerCount(t.count)
                        })), this.protocol.addListener(we.typeName, (e => this.handleWebRtcAnswer(e))), this.protocol.addListener(Ce.typeName, (e => this.handleWebRtcOffer(e))), this.protocol.addListener(Le.typeName, (e => this.handleWebRtcSFUPeerDatachannels(e))), this.protocol.addListener(Te.typeName, (e => {
                            const t = e;
                            this.handleIceCandidate(t.candidate)
                        })), this.protocol.transport.addListener("open", (() => {
                            const e = Ue(pe);
                            this.protocol.sendMessage(e), this.reconnectAttempt = 0, this.isReconnecting = !1
                        })), this.protocol.transport.addListener("error", (() => {
                            a.Vy.Error("Got a transport error.")
                        })), this.protocol.transport.addListener("close", (e => {
                            const t = this.config.getNumericSettingValue(Qe.k$.MaxReconnectAttempts),
                                n = this.reconnectAttempt < t,
                                s = (this.forceReconnect || this.enableAutoReconnect && t > 0 && n) && 1001 != e.code,
                                i = !s,
                                r = this.disconnectMessage ? this.disconnectMessage : e.reason;
                            this.forceReconnect = !1, this.config.getSettingOption(Qe.mY.PreferredCodec).options = jt.C.getSupportedVideoCodecs(), this.pixelStreaming._onDisconnect(r, i), this.afkController.stopAfkWarningTimer(), this.statsTimerHandle && void 0 !== this.statsTimerHandle && window.clearInterval(this.statsTimerHandle), this.setVideoEncoderAvgQP(0), this.setTouchInputEnabled(!1), this.setMouseInputEnabled(!1), this.setKeyboardInputEnabled(!1), this.setGamePadInputEnabled(!1), s && setTimeout((() => {
                                this.reconnectAttempt++, this.doReconnect(e.reason)
                            }), 2e3)
                        })), this.sendMessageController = new Ut(this.dataChannelSender, this.streamMessageController), this.toStreamerMessagesController = new Bt(this.sendMessageController), this.registerMessageHandlers(), this.streamMessageController.populateDefaultProtocol(), this.inputClassesFactory = new Dt(this.streamMessageController, this.videoPlayer, this.coordinateConverter), this.isUsingSFU = !1, this.isUsingSVC = !1, this.isQualityController = !1, this.preferredCodec = "", this.enableAutoReconnect = !0, this.forceReconnect = !1, this.reconnectAttempt = 0, this.isReconnecting = !1, this.config._addOnOptionSettingChangedListener(Qe.mY.StreamerId, (e => {
                            if (void 0 === e || "" === e) return;
                            this.peerConnectionController.peerConnection.close(), this.peerConnectionController.createPeerConnection(this.peerConfig, this.preferredCodec), this.subscribedStream = e;
                            const t = Ue(fe, {
                                streamerId: e
                            });
                            this.protocol.sendMessage(t)
                        })), this.config._addOnOptionSettingChangedListener(Qe.mY.PreferredQuality, (e => {
                            if (void 0 === e || "" === e) return;
                            let t;
                            if (this.isUsingSVC) t = Ue(Pe, {
                                spatialLayer: +e[1] - 1,
                                temporalLayer: +e[3] - 1
                            });
                            else {
                                const n = this.config.getSettingOption(Qe.mY.PreferredQuality).options.indexOf(e);
                                t = Ue(Pe, {
                                    spatialLayer: n,
                                    temporalLayer: 0
                                })
                            }
                            this.protocol.sendMessage(t)
                        })), this.setVideoEncoderAvgQP(-1), this.signallingUrlBuilder = () => this.config.getTextSettingValue(Qe.gw.SignallingServerUrl)
                        window.addEventListener("startAutomatedTest", () => {
                            this.startAutomatedTest?.();
                        })

                    }
                    //función para inicializar el test ---- jose
                    startAutomatedTest(durationMs = 60000) {
                        console.log("▶️ Iniciando test automatizado...");
                        // metricsLog = [metricsHeaders];
                        window.isCollectingTestStats = true;
                        const repeticioneslatency = durationMs / 1000;
                        if (!this.inputHandler){
                            this.inputHandler = new wt(this.streamMessageController, this.config, this.activeKeys);
                        }
                        
                        if(!this.inputMouse){
                            this.inputMouse = new xt(this.streamMessageController, this.videoPlayer, this.coordinateConverter, this.activeKeys);
                            this.inputMouse.register();
                        }
                        this.inputHandler.sendTestKeyInputs(durationMs);
                        this.inputMouse.sendTestMouseInputs(durationMs);
                        let index = 0;
                        const inter = setInterval(() => {
                            if(index >= repeticioneslatency){
                                clearInterval(inter);
                            }
                            index++;
                            this.sendLatencyTest();
                        }, 1000);
                        

                        this._statsTimer = setTimeout(() => {
                            window.isCollectingTestStats = false;
                            //this.downloadCSV(metricsLog);
                            this.downloadCSV(inboundVideoLog,"inboundVideo");
                            this.downloadCSV(remoteOutboundVideoLog,"remoteOutboundVideo");
                            this.downloadCSV(candidatePairLog,"CandidatePair");
                            this.downloadCSV(inboundAudioLog,"inboundAudio");
                            this.downloadCSV(remoteInboundVideoLog, "remoteInboundVideo");
                            this.downloadCSV(latencyLog,"RTT");
                        }, durationMs + 1000);
                    }

                    downloadCSV(rows,nombre) {
                        const csvContent = rows.map(e => e.join(",")).join("\n");
                        const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
                        const url = URL.createObjectURL(blob);

                        const a = document.createElement("a");
                        a.href = url;
                        //a.download = `metrics_test_${Date.now()}.csv`;
                        a.download = `${nombre}.csv`
                        a.style.display = "none";
                        document.body.appendChild(a);
                        a.click();
                        document.body.removeChild(a);
                        URL.revokeObjectURL(url);
                    }


                    // función para la inicialización del test --- jose

                    destroyVideoPlayer() {
                        this.videoPlayer.destroy()
                    }
                    handleOnMessage(e) {
                        const t = new Uint8Array(e.data);
                        a.Vy.Info("Message incoming:" + t);
                        const n = this.streamMessageController.fromStreamerMessages.get(t[0]);
                        this.streamMessageController.fromStreamerHandlers.get(n)(e.data)
                    }
                    registerMessageHandlers() {
                        this.streamMessageController.registerMessageHandler(Lt.FromStreamer, "QualityControlOwnership", (e => this.onQualityControlOwnership(e))), this.streamMessageController.registerMessageHandler(Lt.FromStreamer, "Response", (e => this.responseController.onResponse(e))), this.streamMessageController.registerMessageHandler(Lt.FromStreamer, "Command", (e => {
                            this.onCommand(e)
                        })), this.streamMessageController.registerMessageHandler(Lt.FromStreamer, "FreezeFrame", (e => this.onFreezeFrameMessage(e))), this.streamMessageController.registerMessageHandler(Lt.FromStreamer, "UnfreezeFrame", (() => this.invalidateFreezeFrameAndEnableVideo())), this.streamMessageController.registerMessageHandler(Lt.FromStreamer, "VideoEncoderAvgQP", (e => this.handleVideoEncoderAvgQP(e))), this.streamMessageController.registerMessageHandler(Lt.FromStreamer, "LatencyTest", (e => this.handleLatencyTestResult(e))), this.streamMessageController.registerMessageHandler(Lt.FromStreamer, "DataChannelLatencyTest", (e => this.handleDataChannelLatencyTestResponse(e))), this.streamMessageController.registerMessageHandler(Lt.FromStreamer, "InitialSettings", (e => this.handleInitialSettings(e))), this.streamMessageController.registerMessageHandler(Lt.FromStreamer, "FileExtension", (e => this.onFileExtension(e))), this.streamMessageController.registerMessageHandler(Lt.FromStreamer, "FileMimeType", (e => this.onFileMimeType(e))), this.streamMessageController.registerMessageHandler(Lt.FromStreamer, "FileContents", (e => this.onFileContents(e))), this.streamMessageController.registerMessageHandler(Lt.FromStreamer, "TestEcho", (() => {})), this.streamMessageController.registerMessageHandler(Lt.FromStreamer, "InputControlOwnership", (e => this.onInputControlOwnership(e))), this.streamMessageController.registerMessageHandler(Lt.FromStreamer, "GamepadResponse", (e => this.onGamepadResponse(e))), this.streamMessageController.registerMessageHandler(Lt.FromStreamer, "Multiplexed", (() => {})), this.streamMessageController.registerMessageHandler(Lt.FromStreamer, "Protocol", (e => this.onProtocolMessage(e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "IFrameRequest", (() => this.sendMessageController.sendMessageToStreamer("IFrameRequest"))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "RequestQualityControl", (() => this.sendMessageController.sendMessageToStreamer("RequestQualityControl"))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "FpsRequest", (() => this.sendMessageController.sendMessageToStreamer("FpsRequest"))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "AverageBitrateRequest", (() => this.sendMessageController.sendMessageToStreamer("AverageBitrateRequest"))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "StartStreaming", (() => this.sendMessageController.sendMessageToStreamer("StartStreaming"))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "StopStreaming", (() => this.sendMessageController.sendMessageToStreamer("StopStreaming"))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "LatencyTest", (e => this.sendMessageController.sendMessageToStreamer("LatencyTest", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "RequestInitialSettings", (() => this.sendMessageController.sendMessageToStreamer("RequestInitialSettings"))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "TestEcho", (() => {})), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "UIInteraction", (e => this.sendMessageController.sendMessageToStreamer("UIInteraction", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "Command", (e => this.sendMessageController.sendMessageToStreamer("Command", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "TextboxEntry", (e => this.sendMessageController.sendMessageToStreamer("TextboxEntry", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "KeyDown", (e => this.sendMessageController.sendMessageToStreamer("KeyDown", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "KeyUp", (e => this.sendMessageController.sendMessageToStreamer("KeyUp", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "KeyPress", (e => this.sendMessageController.sendMessageToStreamer("KeyPress", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "MouseEnter", (e => this.sendMessageController.sendMessageToStreamer("MouseEnter", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "MouseLeave", (e => this.sendMessageController.sendMessageToStreamer("MouseLeave", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "MouseDown", (e => this.sendMessageController.sendMessageToStreamer("MouseDown", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "MouseUp", (e => this.sendMessageController.sendMessageToStreamer("MouseUp", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "MouseMove", (e => this.sendMessageController.sendMessageToStreamer("MouseMove", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "MouseWheel", (e => this.sendMessageController.sendMessageToStreamer("MouseWheel", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "MouseDouble", (e => this.sendMessageController.sendMessageToStreamer("MouseDouble", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "TouchStart", (e => this.sendMessageController.sendMessageToStreamer("TouchStart", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "TouchEnd", (e => this.sendMessageController.sendMessageToStreamer("TouchEnd", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "TouchMove", (e => this.sendMessageController.sendMessageToStreamer("TouchMove", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "GamepadConnected", (() => this.sendMessageController.sendMessageToStreamer("GamepadConnected"))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "GamepadButtonPressed", (e => this.sendMessageController.sendMessageToStreamer("GamepadButtonPressed", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "GamepadButtonReleased", (e => this.sendMessageController.sendMessageToStreamer("GamepadButtonReleased", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "GamepadAnalog", (e => this.sendMessageController.sendMessageToStreamer("GamepadAnalog", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "GamepadDisconnected", (e => this.sendMessageController.sendMessageToStreamer("GamepadDisconnected", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "XREyeViews", (e => this.sendMessageController.sendMessageToStreamer("XREyeViews", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "XRHMDTransform", (e => this.sendMessageController.sendMessageToStreamer("XRHMDTransform", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "XRControllerTransform", (e => this.sendMessageController.sendMessageToStreamer("XRControllerTransform", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "XRSystem", (e => this.sendMessageController.sendMessageToStreamer("XRSystem", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "XRButtonTouched", (e => this.sendMessageController.sendMessageToStreamer("XRButtonTouched", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "XRButtonTouchReleased", (e => this.sendMessageController.sendMessageToStreamer("XRButtonTouchReleased", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "XRButtonPressed", (e => this.sendMessageController.sendMessageToStreamer("XRButtonPressed", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "XRButtonReleased", (e => this.sendMessageController.sendMessageToStreamer("XRButtonReleased", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "XRAnalog", (e => this.sendMessageController.sendMessageToStreamer("XRAnalog", e))), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "ChannelRelayStatus", (() => {})), this.streamMessageController.registerMessageHandler(Lt.ToStreamer, "Multiplexed", (() => {}))
                    }
                    onCommand(e) {
                        a.Vy.Info("DataChannelReceiveMessageType.Command");
                        const t = new TextDecoder("utf-16").decode(e.slice(1));
                        a.Vy.Info("Data Channel Command: " + t);
                        const n = JSON.parse(t);
                        "onScreenKeyboard" === n.command && this.handleOnScreenKeyboardCommand(n)
                    }
                    handleOnScreenKeyboardCommand(e) {
                        var t, n, s, i;
                        const r = {
                            showOnScreenKeyboard: null === (t = e.showOnScreenKeyboard) || void 0 === t || t,
                            x: null !== (n = e.x) && void 0 !== n ? n : 0,
                            y: null !== (s = e.y) && void 0 !== s ? s : 0,
                            contents: null !== (i = e.contents) && void 0 !== i ? i : ""
                        };
                        this.pixelStreaming.dispatchEvent(new $e.Gi(r))
                    }
                    onProtocolMessage(e) {
                        try {
                            const t = new TextDecoder("utf-16").decode(e.slice(1)),
                                n = JSON.parse(t);
                            Object.prototype.hasOwnProperty.call(n, "Direction") || a.Vy.Error("Malformed protocol received. Ensure the protocol message contains a direction");
                            const s = n.Direction;
                            delete n.Direction, a.Vy.Info(`Received new ${s==Lt.FromStreamer?"FromStreamer":"ToStreamer"} protocol. Updating existing protocol...`), Object.keys(n).forEach((e => {
                                const t = n[e];
                                switch (s) {
                                    case Lt.ToStreamer:
                                        if (!Object.prototype.hasOwnProperty.call(t, "id")) return void a.Vy.Error(`ToStreamer->${e} protocol definition was malformed as it didn't contain at least an id\n\n                                           Definition was: ${JSON.stringify(t,null,2)}`);
                                        if ("UIInteraction" === e || "Command" === e || "LatencyTest" === e) return;
                                        this.streamMessageController.toStreamerHandlers.get(e) ? this.streamMessageController.toStreamerMessages.set(e, t) : a.Vy.Error(`There was no registered handler for "${e}" - try adding one using registerMessageHandler(MessageDirection.ToStreamer, "${e}", myHandler)`);
                                        break;
                                    case Lt.FromStreamer:
                                        if (!Object.prototype.hasOwnProperty.call(t, "id")) return void a.Vy.Error(`FromStreamer->${e} protocol definition was malformed as it didn't contain at least an id\n\n                            Definition was: ${JSON.stringify(t,null,2)}`);
                                        this.streamMessageController.fromStreamerHandlers.get(e) ? this.streamMessageController.fromStreamerMessages.set(t.id, e) : a.Vy.Error(`There was no registered handler for "${t}" - try adding one using registerMessageHandler(MessageDirection.FromStreamer, "${e}", myHandler)`);
                                        break;
                                    default:
                                        a.Vy.Error(`Unknown direction: ${s}`)
                                }
                            })), this.toStreamerMessagesController.SendRequestInitialSettings(), this.toStreamerMessagesController.SendRequestQualityControl()
                        } catch (e) {
                            a.Vy.Info(e)
                        }
                    }
                    onInputControlOwnership(e) {
                        const t = new Uint8Array(e);
                        a.Vy.Info("DataChannelReceiveMessageType.InputControlOwnership");
                        const n = new Boolean(t[1]).valueOf();
                        a.Vy.Info(`Received input controller message - will your input control the stream: ${n}`), this.pixelStreaming._onInputControlOwnership(n)
                    }
                    onGamepadResponse(e) {
                        const t = new TextDecoder("utf-16").decode(e.slice(1)),
                            n = JSON.parse(t);
                        this.gamePadController.onGamepadResponseReceived(n.controllerId)
                    }
                    onAfkTriggered() {
                        this.afkController.onAfkClick(), this.videoPlayer.isPaused() && this.videoPlayer.hasVideoSource() && this.playStream()
                    }
                    setAfkEnabled(e) {
                        e ? this.onAfkTriggered() : this.afkController.stopAfkWarningTimer()
                    }
                    tryReconnect(e) {
                        this.forceReconnect = !0, this.doReconnect(e)
                    }
                    doReconnect(e) {
                        this.protocol ? (this.isReconnecting = !0, this.protocol.isConnected() ? (this.forceReconnect || (this.disconnectMessage = `${e} Reconnecting.`), this.closeSignalingServer(e, !0)) : (this.pixelStreaming._onWebRtcAutoConnect(), this.connectToSignallingServer())) : a.Vy.Info("This player has no protocol connection.")
                    }
                    loadFreezeFrameOrShowPlayOverlay() {
                        this.pixelStreaming.dispatchEvent(new $e.vx({
                            shouldShowPlayOverlay: this.shouldShowPlayOverlay,
                            isValid: this.freezeFrameController.valid,
                            jpegData: this.freezeFrameController.jpeg
                        })), !0 === this.shouldShowPlayOverlay ? (a.Vy.Info("showing play overlay"), this.resizePlayerStyle()) : (a.Vy.Info("showing freeze frame"), this.freezeFrameController.showFreezeFrame()), setTimeout((() => {
                            this.videoPlayer.setVideoEnabled(!1)
                        }), this.freezeFrameController.freezeFrameDelay)
                    }
                    onFreezeFrameMessage(e) {
                        a.Vy.Info("DataChannelReceiveMessageType.FreezeFrame");
                        const t = new Uint8Array(e);
                        this.freezeFrameController.processFreezeFrameMessage(t, (() => this.loadFreezeFrameOrShowPlayOverlay()))
                    }
                    invalidateFreezeFrameAndEnableVideo() {
                        a.Vy.Info("DataChannelReceiveMessageType.FreezeFrame"), setTimeout((() => {
                            this.pixelStreaming.dispatchEvent(new $e.RW), this.freezeFrameController.hideFreezeFrame()
                        }), this.freezeFrameController.freezeFrameDelay), this.videoPlayer.getVideoElement() && this.videoPlayer.setVideoEnabled(!0)
                    }
                    onFileExtension(e) {
                        const t = new Uint8Array(e);
                        vt.setExtensionFromBytes(t, this.file)
                    }
                    onFileMimeType(e) {
                        const t = new Uint8Array(e);
                        vt.setMimeTypeFromBytes(t, this.file)
                    }
                    onFileContents(e) {
                        const t = new Uint8Array(e);
                        vt.setContentsFromBytes(t, this.file)
                    }
                    playStream() {
                        if (!this.videoPlayer.getVideoElement()) {
                            const e = "Could not play video stream because the video player was not initialized correctly.";
                            return this.pixelStreaming.dispatchEvent(new $e.vL({
                                message: e
                            })), a.Vy.Error(e), void this.closeSignalingServer("Stream not initialized correctly", !1)
                        }
                        if (this.videoPlayer.hasVideoSource()) {
                            if (this.setTouchInputEnabled(this.config.isFlagEnabled(Qe.iI.TouchInput)), this.pixelStreaming.dispatchEvent(new $e.Lz), this.streamController.audioElement.srcObject) {
                                const e = this.config.isFlagEnabled(Qe.iI.StartVideoMuted);
                                this.streamController.audioElement.muted = e, e ? this.playVideo() : this.streamController.audioElement.play().then((() => {
                                    this.playVideo()
                                })).catch((e => {
                                    a.Vy.Info(e), a.Vy.Info("Browser does not support autoplaying video without interaction - to resolve this we are going to show the play button overlay."), this.pixelStreaming.dispatchEvent(new $e.FJ({
                                        reason: e
                                    }))
                                }))
                            } else this.playVideo();
                            this.shouldShowPlayOverlay = !1, this.freezeFrameController.showFreezeFrame()
                        } else a.Vy.Warning("Cannot play stream, the video element has no srcObject to play.")
                    }
                    playVideo() {
                        this.videoPlayer.play().catch((e => {
                            this.streamController.audioElement.srcObject && this.streamController.audioElement.pause(), a.Vy.Info(e), a.Vy.Info("Browser does not support autoplaying video without interaction - to resolve this we are going to show the play button overlay."), this.pixelStreaming.dispatchEvent(new $e.FJ({
                                reason: e
                            }))
                        }))
                    }
                    autoPlayVideoOrSetUpPlayOverlay() {
                        this.config.isFlagEnabled(Qe.iI.AutoPlayVideo) && this.playStream(), this.resizePlayerStyle()
                    }
                    connectToSignallingServer() {
                        this.locallyClosed = !1, this.enableAutoReconnect = !0, this.disconnectMessage = null;
                        const e = this.signallingUrlBuilder();
                        this.protocol.connect(e);
                        const t = this.config.getNumericSettingValue(Qe.k$.KeepaliveDelay);
                        t > 0 && (this.keepalive = new We(this.protocol, t), this.keepalive.onTimeout = () => {
                            a.Vy.Error("Protocol timeout"), this.protocol.disconnect()
                        })
                    }
                    startSession(e) {
                        if (this.peerConfig = e, this.config.isFlagEnabled(Qe.iI.ForceTURN)) {
                            if (!this.checkTurnServerAvailability(e)) return a.Vy.Info("No turn server was found in the Peer Connection Options. TURN cannot be forced, closing connection. Please use STUN instead"), void this.closeSignalingServer("TURN cannot be forced, closing connection. Please use STUN instead.", !1)
                        }
                        this.peerConnectionController = new ut(this.peerConfig, this.config, this.preferredCodec), this.peerConnectionController.onVideoStats = e => {
                            this.handleVideoStats(e)
                        }, this.peerConnectionController.onLatencyCalculated = e => {
                            this.pixelStreaming._onLatencyCalculated(e)
                        }, this.peerConnectionController.onSendWebRTCOffer = e => {
                            this.handleSendWebRTCOffer(e)
                        }, this.peerConnectionController.onSetLocalDescription = e => {
                            this.handleSendWebRTCAnswer(e)
                        }, this.peerConnectionController.onSetRemoteDescription = e => {
                            this.pixelStreaming._onWebRtcSdpOffer(e)
                        }, this.peerConnectionController.onPeerIceCandidate = e => this.handleSendIceCandidate(e), this.peerConnectionController.onDataChannel = e => this.handleDataChannel(e), this.peerConnectionController.showTextOverlayConnecting = () => this.pixelStreaming._onWebRtcConnecting(), this.peerConnectionController.showTextOverlaySetupFailure = () => this.pixelStreaming._onWebRtcFailed();
                        let t = !1;
                        this.peerConnectionController.onIceConnectionStateChange = () => {
                            !t && ["connected", "completed"].includes(this.peerConnectionController.peerConnection.iceConnectionState) && (this.pixelStreaming._onWebRtcConnected(), t = !0)
                        }, this.peerConnectionController.onTrack = e => this.streamController.handleOnTrack(e)
                    }
                    checkTurnServerAvailability(e) {
                        if (!e.iceServers) return a.Vy.Info("A turn sever was not found"), !1;
                        for (const t of e.iceServers)
                            for (const e of t.urls)
                                if (e.includes("turn")) return a.Vy.Info(`A turn sever was found at ${e}`), !0;
                        return a.Vy.Info("A turn sever was not found"), !1
                    }
                    handleOnConfigMessage(e) {
                        this.resizePlayerStyle(), this.startSession(e.peerConnectionOptions)
                    }
                    handlePingMessage(e) {
                        this.protocol.sendMessage(Ue(ke, {
                            time: e.time
                        }))
                    }
                    handleStreamerListMessage(e) {
                        a.Vy.Info(`Got streamer list ${e.ids}`);
                        let t = "";
                        const n = this.config.getSettingOption(Qe.mY.StreamerId);
                        n.selected.toString().trim() && (t = n.selected);
                        const s = [...e.ids];
                        s.unshift(""), this.config.setOptionSettingOptions(Qe.mY.StreamerId, s);
                        let i = "";
                        const r = this.config.isFlagEnabled(Qe.iI.WaitForStreamer),
                            o = this.config.getNumericSettingValue(Qe.k$.MaxReconnectAttempts),
                            l = this.config.getNumericSettingValue(Qe.k$.StreamerAutoJoinInterval),
                            c = this.config.useUrlParams,
                            d = new Ht(window.location.search);
                        c && d.has(Qe.mY.StreamerId) ? t = d.get(Qe.mY.StreamerId) : this.subscribedStream && (t = this.subscribedStream), t && e.ids.includes(t) ? i = t : t && r || 1 != e.ids.length || (i = e.ids[0]), i ? (this.reconnectAttempt = 0, this.isReconnecting = !1, this.config.setOptionSettingValue(Qe.mY.StreamerId, i)) : r && (this.reconnectAttempt < o ? (this.reconnectAttempt++, this.isReconnecting = !0, setTimeout((() => {
                            this.protocol.sendMessage(Ue(pe))
                        }), l)) : (this.reconnectAttempt = 0, this.isReconnecting = !1, this.enableAutoReconnect = !1)), this.pixelStreaming.dispatchEvent(new $e.jG({
                            messageStreamerList: e,
                            autoSelectedStreamerId: i,
                            wantedStreamerId: t
                        }))
                    }
                    handleSubscribeFailedMessage(e) {
                        this.reconnectAttempt = 0, this.isReconnecting = !1, this.enableAutoReconnect = !1, this.pixelStreaming._onSubscribeFailed(e.message)
                    }
                    handleStreamerIDChangedMessage(e) {
                        const t = e.newID,
                            n = this.config.getSettingOption(Qe.mY.StreamerId),
                            s = n.onChange;
                        n.onChange = () => {};
                        const i = n.options;
                        for (let e = 0; e < i.length; ++e)
                            if (i[e] == this.subscribedStream) {
                                i[e] = t;
                                break
                            } n.options = i, n.selected = t, n.onChange = s, this.subscribedStream = e.newID, this.pixelStreaming.dispatchEvent(new $e.ie({
                            newID: t
                        }))
                    }
                    handleWebRtcAnswer(e) {
                        a.Vy.Info(`Got answer sdp ${e.sdp}`);
                        const t = {
                            sdp: e.sdp,
                            type: "answer"
                        };
                        this.peerConnectionController.receiveAnswer(t), this.handlePostWebrtcNegotiation()
                    }
                    handleWebRtcOffer(e) {
                        a.Vy.Info(`Got offer sdp ${e.sdp}`), this.isUsingSFU = !!e.sfu && e.sfu, this.isUsingSVC = !!e.scalabilityMode && "L1T1" != e.scalabilityMode, (this.isUsingSFU || this.isUsingSVC) && (this.peerConnectionController.preferredCodec = "");
                        const t = e.scalabilityMode ? e.scalabilityMode : "L1T1";
                        let n = ["Default"];
                        if (this.isUsingSFU)
                            if (this.isUsingSVC) {
                                n = [];
                                const e = +t[1],
                                    s = +t[3];
                                for (let t = 1; t <= e; t++)
                                    for (let e = 1; e <= s; e++) n.push(`S${t}T${e}`)
                            } else n = ["Low", "Medium", "High"];
                        this.config.setOptionSettingOptions(Qe.mY.PreferredQuality, n), this.config.setOptionSettingValue(Qe.mY.PreferredQuality, n.slice(-1)[0]);
                        const s = {
                            sdp: e.sdp,
                            type: "offer"
                        };
                        this.peerConnectionController.receiveOffer(s, this.config), this.handlePostWebrtcNegotiation()
                    }
                    handleWebRtcSFUPeerDatachannels(e) {
                        const t = {
                                ordered: !0,
                                negotiated: !0,
                                id: e.sendStreamId
                            },
                            n = e.sendStreamId != e.recvStreamId;
                        if (this.sendrecvDataChannelController.createDataChannel(this.peerConnectionController.peerConnection, n ? "send-datachannel" : "datachannel", t), n) {
                            const t = {
                                ordered: !0,
                                negotiated: !0,
                                id: e.recvStreamId
                            };
                            this.recvDataChannelController.createDataChannel(this.peerConnectionController.peerConnection, "recv-datachannel", t), this.recvDataChannelController.handleOnOpen = () => this.protocol.sendMessage(Ue(Oe)), this.recvDataChannelController.handleOnMessage = e => this.handleOnMessage(e)
                        } else this.sendrecvDataChannelController.handleOnMessage = e => this.handleOnMessage(e)
                    }
                    handlePostWebrtcNegotiation() {
                        this.afkController.startAfkWarningTimer(), this.pixelStreaming._onWebRtcSdp(), this.statsTimerHandle && void 0 !== this.statsTimerHandle && window.clearInterval(this.statsTimerHandle), this.statsTimerHandle = window.setInterval((() => this.getStats()), 1e3), this.setMouseInputEnabled(this.config.isFlagEnabled(Qe.iI.MouseInput)), this.setKeyboardInputEnabled(this.config.isFlagEnabled(Qe.iI.KeyboardInput)), this.setGamePadInputEnabled(this.config.isFlagEnabled(Qe.iI.GamepadInput))
                    }
                    handleIceCandidate(e) {
                        a.Vy.Info("Web RTC Controller: onWebRtcIce");
                        const t = new RTCIceCandidate(e);
                        this.peerConnectionController.handleOnIce(t)
                    }
                    handleSendIceCandidate(e) {
                        a.Vy.Info("OnIceCandidate"), e.candidate && e.candidate.candidate && this.protocol.sendMessage(Ue(Te, {
                            candidate: e.candidate
                        }))
                    }
                    handleDataChannel(e) {
                        a.Vy.Info("Data channel created for us by browser as we are a receiving peer."), this.sendrecvDataChannelController.dataChannel = e.channel, this.sendrecvDataChannelController.setupDataChannel(), this.sendrecvDataChannelController.handleOnMessage = e => this.handleOnMessage(e)
                    }
                    handleSendWebRTCOffer(e) {
                        a.Vy.Info("Sending the offer to the Server");
                        const t = {
                            sdp: e.sdp,
                            minBitrateBps: 1e3 * this.config.getNumericSettingValue(Qe.k$.WebRTCMinBitrate),
                            maxBitrateBps: 1e3 * this.config.getNumericSettingValue(Qe.k$.WebRTCMaxBitrate)
                        };
                        this.protocol.sendMessage(Ue(Ce, t))
                    }
                    handleSendWebRTCAnswer(e) {
                        a.Vy.Info("Sending the answer to the Server");
                        const t = {
                            sdp: e.sdp,
                            minBitrateBps: 1e3 * this.config.getNumericSettingValue(Qe.k$.WebRTCMinBitrate),
                            maxBitrateBps: 1e3 * this.config.getNumericSettingValue(Qe.k$.WebRTCMaxBitrate)
                        };
                        this.protocol.sendMessage(Ue(we, t)), this.isUsingSFU && this.protocol.sendMessage(Ue(Ie)), this.pixelStreaming._onWebRtcSdpAnswer(e)
                    }
                    setUpMouseAndFreezeFrame() {
                        const e = this.videoPlayer.getVideoParentElement(),
                            t = this.videoPlayer.getVideoElement();
                        this.coordinateConverter.reconfigure({
                            width: e.clientWidth,
                            height: e.clientHeight
                        }, {
                            width: t.videoWidth,
                            height: t.videoHeight
                        }), this.freezeFrameController.freezeFrame.resize()
                    }
                    closeSignalingServer(e, t) {
                        var n;
                        this.locallyClosed = !0, this.enableAutoReconnect = t, this.disconnectMessage = e, null === (n = this.protocol) || void 0 === n || n.disconnect(1e3, e)
                    }
                    closePeerConnection() {
                        var e;
                        null === (e = this.peerConnectionController) || void 0 === e || e.close()
                    }
                    close() {
                        this.closeSignalingServer("", !1), this.closePeerConnection()
                    }
                    getStats() {
                        this.peerConnectionController.generateStats()
                    }
                    sendLatencyTest() {
                        this.latencyStartTime = Date.now(), this.streamMessageController.toStreamerHandlers.get("LatencyTest")([JSON.stringify({
                            StartTime: this.latencyStartTime
                        })])
                    }
                    sendDataChannelLatencyTest(e) {
                        this.streamMessageController.toStreamerHandlers.get("DataChannelLatencyTest")([JSON.stringify(e)])
                    }
                    sendEncoderMinQP(e) {
                        a.Vy.Info(`MinQP=${e}\n`), null != e && this.streamMessageController.toStreamerHandlers.get("Command")([JSON.stringify({
                            "Encoder.MinQP": e
                        })])
                    }
                    sendEncoderMaxQP(e) {
                        a.Vy.Info(`MaxQP=${e}\n`), null != e && this.streamMessageController.toStreamerHandlers.get("Command")([JSON.stringify({
                            "Encoder.MaxQP": e
                        })])
                    }
                    sendEncoderMinQuality(e) {
                        a.Vy.Info(`MinQuality=${e}\n`), null != e && this.streamMessageController.toStreamerHandlers.get("Command")([JSON.stringify({
                            "Encoder.MinQuality": e
                        })])
                    }
                    sendEncoderMaxQuality(e) {
                        a.Vy.Info(`MaxQuality=${e}\n`), null != e && this.streamMessageController.toStreamerHandlers.get("Command")([JSON.stringify({
                            "Encoder.MaxQuality": e
                        })])
                    }
                    sendWebRTCMinBitrate(e) {
                        a.Vy.Info(`WebRTC Min Bitrate=${e}`), null != e && this.streamMessageController.toStreamerHandlers.get("Command")([JSON.stringify({
                            "WebRTC.MinBitrate": e
                        })])
                    }
                    sendWebRTCMaxBitrate(e) {
                        a.Vy.Info(`WebRTC Max Bitrate=${e}`), null != e && this.streamMessageController.toStreamerHandlers.get("Command")([JSON.stringify({
                            "WebRTC.MaxBitrate": e
                        })])
                    }
                    sendWebRTCFps(e) {
                        a.Vy.Info(`WebRTC FPS=${e}`), null != e && (this.streamMessageController.toStreamerHandlers.get("Command")([JSON.stringify({
                            "WebRTC.Fps": e
                        })]), this.streamMessageController.toStreamerHandlers.get("Command")([JSON.stringify({
                            "WebRTC.MaxFps": e
                        })]))
                    }
                    sendShowFps() {
                        a.Vy.Info("----   Sending show stat to UE   ----"), this.streamMessageController.toStreamerHandlers.get("Command")([JSON.stringify({
                            "stat.fps": ""
                        })])
                    }
                    sendIframeRequest() {
                        a.Vy.Info("----   Sending Request for an IFrame  ----"), this.streamMessageController.toStreamerHandlers.get("IFrameRequest")()
                    }
                    emitUIInteraction(e) {
                        a.Vy.Info("----   Sending custom UIInteraction message   ----"), this.streamMessageController.toStreamerHandlers.get("UIInteraction")([JSON.stringify(e)])
                    }
                    emitCommand(e) {
                        a.Vy.Info("----   Sending custom Command message   ----"), this.streamMessageController.toStreamerHandlers.get("Command")([JSON.stringify(e)])
                    }
                    emitConsoleCommand(e) {
                        a.Vy.Info("----   Sending custom Command:ConsoleCommand message   ----"), this.streamMessageController.toStreamerHandlers.get("Command")([JSON.stringify({
                            ConsoleCommand: e
                        })])
                    }
                    sendRequestQualityControlOwnership() {
                        a.Vy.Info("----   Sending Request to Control Quality  ----"), this.toStreamerMessagesController.SendRequestQualityControl()
                    }
                    sendTextboxEntry(e) {
                        var t;
                        a.Vy.Info("----   Sending TextboxEntry message  ----"), null === (t = this.streamMessageController.toStreamerHandlers.get("TextboxEntry")) || void 0 === t || t([e])
                    }
                    handleLatencyTestResult(e) {
                        a.Vy.Info("DataChannelReceiveMessageType.latencyTest");
                        const t = new TextDecoder("utf-16").decode(e.slice(1)),
                            n = new yt;
                        Object.assign(n, JSON.parse(t)), n.processFields(), n.testStartTimeMs = this.latencyStartTime, n.browserReceiptTimeMs = Date.now(), n.latencyExcludingDecode = ~~(n.browserReceiptTimeMs - n.testStartTimeMs), n.testDuration = ~~(n.TransmissionTimeMs - n.ReceiptTimeMs), n.networkLatency = ~~(n.latencyExcludingDecode - n.testDuration), n.frameDisplayDeltaTimeMs && n.browserReceiptTimeMs && (n.endToEndLatency = (n.frameDisplayDeltaTimeMs, n.networkLatency, ~~+n.CaptureToSendMs)), this.pixelStreaming._onLatencyTestResult(n)
                    }
                    handleDataChannelLatencyTestResponse(e) {
                        a.Vy.Info("DataChannelReceiveMessageType.dataChannelLatencyResponse");
                        const t = new TextDecoder("utf-16").decode(e.slice(1)),
                            n = JSON.parse(t);
                        this.pixelStreaming._onDataChannelLatencyTestResponse(n)
                    }
                    handleInitialSettings(e) {
                        a.Vy.Info("DataChannelReceiveMessageType.InitialSettings");
                        const t = new TextDecoder("utf-16").decode(e.slice(1)),
                            n = JSON.parse(t),
                            s = new mt;
                        n.Encoder && (s.EncoderSettings = n.Encoder), n.WebRTC && (s.WebRTCSettings = n.WebRTC), n.PixelStreaming && (s.PixelStreamingSettings = n.PixelStreaming), n.ConfigOptions && void 0 !== n.ConfigOptions.DefaultToHover && this.config.setFlagEnabled(Qe.iI.HoveringMouseMode, !!n.ConfigOptions.DefaultToHover), s.ueCompatible(), a.Vy.Info(t), this.pixelStreaming._onInitialSettings(s)
                    }
                    handleVideoEncoderAvgQP(e) {
                        a.Vy.Info("DataChannelReceiveMessageType.VideoEncoderAvgQP");
                        const t = Number(new TextDecoder("utf-16").decode(e.slice(1)));
                        this.setVideoEncoderAvgQP(t)
                    }
                    handleVideoInitialized() {
                        this.pixelStreaming._onVideoInitialized(), this.autoPlayVideoOrSetUpPlayOverlay(), this.resizePlayerStyle(), this.videoPlayer.updateVideoStreamSize()
                    }
                    onQualityControlOwnership(e) {
                        const t = new Uint8Array(e);
                        a.Vy.Info("DataChannelReceiveMessageType.QualityControlOwnership"), this.isQualityController = new Boolean(t[1]).valueOf(), a.Vy.Info(`Received quality controller message, will control quality: ${this.isQualityController}`), this.pixelStreaming._onQualityControlOwnership(this.isQualityController)
                    }
                    handleVideoStats(e) {
                        this.pixelStreaming._onVideoStats(e)
                    }
                    resizePlayerStyle() {
                        this.videoPlayer.resizePlayerStyle()
                    }
                    setPreferredCodec(e) {
                        this.preferredCodec = e, this.peerConnectionController && (this.peerConnectionController.preferredCodec = e, this.peerConnectionController.updateCodecSelection = !1)
                    }
                    setVideoEncoderAvgQP(e) {
                        this.videoAvgQp = e, this.pixelStreaming._onVideoEncoderAvgQP(this.videoAvgQp)
                    }
                    setKeyboardInputEnabled(e) {
                        var t;
                        null === (t = this.keyboardController) || void 0 === t || t.unregister(), e && (this.keyboardController = this.inputClassesFactory.registerKeyBoard(this.config))
                    }
                    setMouseInputEnabled(e) {
                        var t;
                        if (null === (t = this.mouseController) || void 0 === t || t.unregister(), e) {
                            const e = this.config.isFlagEnabled(Qe.iI.HoveringMouseMode) ? Qe.Bs.HoveringMouse : Qe.Bs.LockedMouse;
                            this.mouseController = this.inputClassesFactory.registerMouse(e)
                        }
                    }
                    setTouchInputEnabled(e) {
                        var t;
                        null === (t = this.touchController) || void 0 === t || t.unregister(), e && (this.touchController = this.inputClassesFactory.registerTouch(this.config.isFlagEnabled(Qe.iI.FakeMouseWithTouches)))
                    }
                    setGamePadInputEnabled(e) {
                        var t;
                        null === (t = this.gamePadController) || void 0 === t || t.unregister(), e && (this.gamePadController = this.inputClassesFactory.registerGamePad())
                    }
                    registerDataChannelEventEmitters(e) {
                        e.onOpen = (e, t) => this.pixelStreaming.dispatchEvent(new $e.ys({
                            label: e,
                            event: t
                        })), e.onClose = (e, t) => this.pixelStreaming.dispatchEvent(new $e.CE({
                            label: e,
                            event: t
                        })), e.onError = (e, t) => this.pixelStreaming.dispatchEvent(new $e.EQ({
                            label: e,
                            event: t
                        }))
                    }
                    registerMessageHandler(e, t, n) {
                        t === Lt.FromStreamer && void 0 === n && a.Vy.Warning(`Unable to register handler for ${e} as no handler was passed`), this.streamMessageController.registerMessageHandler(t, e, (s => void 0 === n && t === Lt.ToStreamer ? this.sendMessageController.sendMessageToStreamer(e, s) : n(s)))
                    }
                }
                var $t = n(359),
                    Kt = n(107),
                    Gt = n(952),
                    qt = n(683),
                    Xt = n(671),
                    Jt = n(613);
                class Yt {
                    constructor(e) {
                        this.seq = e.Seq, this.playerSentTimestamp = Date.now(), this.requestFillerSize = e.Filler ? e.Filler.length : 0
                    }
                    update(e) {
                        this.playerReceivedTimestamp = Date.now(), this.streamerReceivedTimestamp = e.ReceivedTimestamp, this.streamerSentTimestamp = e.SentTimestamp, this.responseFillerSize = e.Filler ? e.Filler.length : 0
                    }
                }
                class Zt {
                    constructor(e, t) {
                        this.intervalHandle = void 0, this.sink = e, this.callback = t, this.records = new Map, this.seq = 0
                    }
                    start(e) {
                        return !this.isRunning() && (this.startTime = Date.now(), this.records.clear(), this.intervalHandle = window.setInterval((() => {
                            Date.now() - this.startTime >= e.duration ? this.stop() : this.sendRequest(e.requestSize, e.responseSize)
                        }).bind(this), Math.floor(1e3 / e.rps)), !0)
                    }
                    stop() {
                        this.intervalHandle && (window.clearInterval(this.intervalHandle), this.intervalHandle = void 0, this.callback(this.produceResult()))
                    }
                    produceResult() {
                        const e = new Map(this.records);
                        return {
                            records: e,
                            dataChannelRtt: Math.ceil(Array.from(this.records.values()).reduce(((e, t) => e + (t.playerReceivedTimestamp - t.playerSentTimestamp)), 0) / this.records.size),
                            playerToStreamerTime: Math.ceil(Array.from(this.records.values()).reduce(((e, t) => e + (t.streamerReceivedTimestamp - t.playerSentTimestamp)), 0) / this.records.size),
                            streamerToPlayerTime: Math.ceil(Array.from(this.records.values()).reduce(((e, t) => e + (t.playerReceivedTimestamp - t.streamerSentTimestamp)), 0) / this.records.size),
                            exportLatencyAsCSV: () => {
                                let t = "Timestamp;RTT;PlayerToStreamer;StreamerToPlayer;\n";
                                return e.forEach((e => {
                                    t += e.playerSentTimestamp + ";", t += e.playerReceivedTimestamp - e.playerSentTimestamp + ";", t += e.streamerReceivedTimestamp - e.playerSentTimestamp + ";", t += e.playerReceivedTimestamp - e.streamerSentTimestamp + ";", t += "\n"
                                })), t
                            }
                        }
                    }
                    isRunning() {
                        return !!this.intervalHandle
                    }
                    receive(e) {
                        if (!this.isRunning()) return;
                        if (!e) return void a.Vy.Error("Undefined response from server");
                        const t = this.records.get(e.Seq);
                        t && t.update(e)
                    }
                    sendRequest(e, t) {
                        const n = this.createRequest(e, t),
                            s = new Yt(n);
                        this.records.set(s.seq, s), this.sink(n)
                    }
                    createRequest(e, t) {
                        return {
                            Seq: this.seq++,
                            FillResponseSize: t,
                            Filler: e ? "A".repeat(e) : ""
                        }
                    }
                }
                class en {
                    constructor(e, t) {
                        this.allowConsoleCommands = !1, this.config = e, (null == t ? void 0 : t.videoElementParent) && (this._videoElementParent = t.videoElementParent), this._eventEmitter = new $e.R5, this.configureSettings(), this.setWebRtcPlayerController(new Qt(this.config, this)), this._webXrController = new $t.R(this._webRtcController), this._setupWebRtcTCPRelayDetection = this._setupWebRtcTCPRelayDetection.bind(this), this._eventEmitter.addEventListener("webRtcConnected", (e => {
                            this._eventEmitter.addEventListener("statsReceived", this._setupWebRtcTCPRelayDetection)
                        }))
                    }
                    get videoElementParent() {
                        return this._videoElementParent || (this._videoElementParent = document.createElement("div"), this._videoElementParent.id = "videoElementParent"), this._videoElementParent
                    }
                    configureSettings() {
                        this.config._addOnSettingChangedListener(Qe.iI.IsQualityController, (e => {
                            !0 !== e || this._webRtcController.isQualityController || this._webRtcController.sendRequestQualityControlOwnership()
                        })), this.config._addOnSettingChangedListener(Qe.iI.AFKDetection, (e => {
                            this._webRtcController.setAfkEnabled(e)
                        })), this.config._addOnSettingChangedListener(Qe.iI.MatchViewportResolution, (() => {
                            this._webRtcController.videoPlayer.updateVideoStreamSize()
                        })), this.config._addOnSettingChangedListener(Qe.iI.HoveringMouseMode, (e => {
                            this.config.setFlagLabel(Qe.iI.HoveringMouseMode, `Control Scheme: ${e?"Hovering":"Locked"} Mouse`), this._webRtcController.setMouseInputEnabled(this.config.isFlagEnabled(Qe.iI.MouseInput))
                        })), this.config._addOnSettingChangedListener(Qe.iI.KeyboardInput, (e => {
                            this._webRtcController.setKeyboardInputEnabled(e)
                        })), this.config._addOnSettingChangedListener(Qe.iI.MouseInput, (e => {
                            this._webRtcController.setMouseInputEnabled(e)
                        })), this.config._addOnSettingChangedListener(Qe.iI.FakeMouseWithTouches, (e => {
                            this._webRtcController.setTouchInputEnabled(this.config.isFlagEnabled(Qe.iI.TouchInput))
                        })), this.config._addOnSettingChangedListener(Qe.iI.TouchInput, (e => {
                            this._webRtcController.setTouchInputEnabled(e)
                        })), this.config._addOnSettingChangedListener(Qe.iI.GamepadInput, (e => {
                            this._webRtcController.setGamePadInputEnabled(e)
                        })), this.config._addOnNumericSettingChangedListener(Qe.k$.MinQP, (e => {
                            a.Vy.Info("--------  Sending MinQP  --------"), this._webRtcController.sendEncoderMinQP(e), a.Vy.Info("-------------------------------------------");
                            const t = Math.trunc(100 * (1 - e / 51));
                            this.config.setNumericSetting(Qe.k$.CompatQualityMax, t)
                        })), this.config._addOnNumericSettingChangedListener(Qe.k$.MaxQP, (e => {
                            a.Vy.Info("--------  Sending MaxQP  --------"), this._webRtcController.sendEncoderMaxQP(e), a.Vy.Info("-------------------------------------------");
                            const t = Math.trunc(100 * (1 - e / 51));
                            this.config.setNumericSetting(Qe.k$.CompatQualityMin, t)
                        })), this.config._addOnNumericSettingChangedListener(Qe.k$.MinQuality, (e => {
                            a.Vy.Info("--------  Sending MinQuality  --------"), this._webRtcController.sendEncoderMinQuality(e), a.Vy.Info("-------------------------------------------"), this.config.setNumericSetting(Qe.k$.CompatQualityMin, e)
                        })), this.config._addOnNumericSettingChangedListener(Qe.k$.MaxQuality, (e => {
                            a.Vy.Info("--------  Sending MaxQuality  --------"), this._webRtcController.sendEncoderMaxQuality(e), a.Vy.Info("-------------------------------------------"), this.config.setNumericSetting(Qe.k$.CompatQualityMax, e)
                        })), this.config._addOnNumericSettingChangedListener(Qe.k$.CompatQualityMin, (e => {
                            e = 51 - e / 100 * 51, a.Vy.Info("--------  Sending MinQP from quality value  --------"), this._webRtcController.sendEncoderMaxQP(e), a.Vy.Info("-------------------------------------------")
                        })), this.config._addOnNumericSettingChangedListener(Qe.k$.CompatQualityMax, (e => {
                            e = 51 - e / 100 * 51, a.Vy.Info("--------  Sending MaxQP from quality value  --------"), this._webRtcController.sendEncoderMinQP(e), a.Vy.Info("-------------------------------------------")
                        })), this.config._addOnNumericSettingChangedListener(Qe.k$.WebRTCMinBitrate, (e => {
                            a.Vy.Info("--------  Sending web rtc settings  --------"), this._webRtcController.sendWebRTCMinBitrate(1e3 * e), a.Vy.Info("-------------------------------------------")
                        })), this.config._addOnNumericSettingChangedListener(Qe.k$.WebRTCMaxBitrate, (e => {
                            a.Vy.Info("--------  Sending web rtc settings  --------"), this._webRtcController.sendWebRTCMaxBitrate(1e3 * e), a.Vy.Info("-------------------------------------------")
                        })), this.config._addOnNumericSettingChangedListener(Qe.k$.WebRTCFPS, (e => {
                            a.Vy.Info("--------  Sending web rtc settings  --------"), this._webRtcController.sendWebRTCFps(e), a.Vy.Info("-------------------------------------------")
                        })), this.config._addOnOptionSettingChangedListener(Qe.mY.PreferredCodec, (e => {
                            this._webRtcController && this._webRtcController.setPreferredCodec(e)
                        })), this.config._registerOnChangeEvents(this._eventEmitter)
                    }
                    _onInputControlOwnership(e) {
                        this._inputController = e
                    }
                    setWebRtcPlayerController(e) {
                        this._webRtcController = e;
                        this._webRtcController.setPreferredCodec(
                            this.config.getSettingOption(Qe.mY.PreferredCodec).selected
                        );
                        this._webRtcController.resizePlayerStyle();
                        this.checkForAutoConnect();

                        // manejador boton --- nos aseguremos que el dom este listo --- jose
                        const button = document.getElementById("startTestButton");
                        if (button) {
                            button.addEventListener("click", () => {
                                const startEvent = new Event("startAutomatedTest");
                                window.dispatchEvent(startEvent)
                            });
                        } else {
                            console.warn("Botón 'startTestButton' no encontrado en el DOM.");
                        }

                        //manejador boton ----- jose
                    }
                    connect() {
                        this._eventEmitter.dispatchEvent(new $e.y6), this._webRtcController.connectToSignallingServer()
                    }
                    reconnect() {
                        this._eventEmitter.dispatchEvent(new $e.oK), this._webRtcController.tryReconnect("Reconnecting...")
                    }
                    disconnect() {
                        this._eventEmitter.dispatchEvent(new $e.iu), this._webRtcController.close()
                    }
                    play() {
                        this._onStreamLoading(), this._webRtcController.playStream()
                    }
                    checkForAutoConnect() {
                        this.config.isFlagEnabled(Qe.iI.AutoConnect) && (this._onWebRtcAutoConnect(), this._webRtcController.connectToSignallingServer())
                    }
                    unmuteMicrophone(e = !1) {
                        if (!this.config.isFlagEnabled("UseMic")) return e ? (this.config.setFlagEnabled("UseMic", !0), void this.reconnect()) : void a.Vy.Warning("Trying to unmute mic, but PixelStreaming was initialized with no microphone track. Call with forceEnable == true to re-connect with a mic track.");
                        this.setMicrophoneMuted(!1)
                    }
                    muteMicrophone() {
                        this.config.isFlagEnabled("UseMic") ? this.setMicrophoneMuted(!0) : a.Vy.Info("Trying to mute mic, but PixelStreaming has no microphone track, so sending sound is already disabled.")
                    }
                    setMicrophoneMuted(e) {
                        var t, n, s, i;
                        for (const r of null !== (i = null === (s = null === (n = null === (t = this._webRtcController) || void 0 === t ? void 0 : t.peerConnectionController) || void 0 === n ? void 0 : n.peerConnection) || void 0 === s ? void 0 : s.getTransceivers()) && void 0 !== i ? i : []) rt.canTransceiverSendAudio(r) && (r.sender.track.enabled = !e)
                    }
                    unmuteCamera(e = !1) {
                        if (!this.config.isFlagEnabled("UseCamera")) return e ? (this.config.setFlagEnabled("UseCamera", !0), void this.reconnect()) : void a.Vy.Warning("Trying to unmute video, but PixelStreaming was initialized with no video track. Call with forceEnable == true to re-connect with a video track.");
                        this.setCameraMuted(!1)
                    }
                    muteCamera() {
                        this.config.isFlagEnabled("UseCamera") ? this.setCameraMuted(!0) : a.Vy.Info("Trying to mute camera, but PixelStreaming has no video track, so sending video is already disabled.")
                    }
                    setCameraMuted(e) {
                        var t, n, s, i;
                        for (const r of null !== (i = null === (s = null === (n = null === (t = this._webRtcController) || void 0 === t ? void 0 : t.peerConnectionController) || void 0 === n ? void 0 : n.peerConnection) || void 0 === s ? void 0 : s.getTransceivers()) && void 0 !== i ? i : []) rt.canTransceiverSendVideo(r) && (r.sender.track.enabled = !e)
                    }
                    _onWebRtcAutoConnect() {
                        this._eventEmitter.dispatchEvent(new $e.nV)
                    }
                    _onWebRtcSdp() {
                        this._eventEmitter.dispatchEvent(new $e.xV)
                    }
                    _onWebRtcSdpOffer(e) {
                        this._eventEmitter.dispatchEvent(new $e.PC({
                            sdp: e
                        }))
                    }
                    _onWebRtcSdpAnswer(e) {
                        this._eventEmitter.dispatchEvent(new $e.zx({
                            sdp: e
                        }))
                    }
                    _onLatencyCalculated(e) {
                        this._eventEmitter.dispatchEvent(new $e.L0({
                            latencyInfo: e
                        }))
                    }
                    _onStreamLoading() {
                        this._eventEmitter.dispatchEvent(new $e.Bg)
                    }
                    _onDisconnect(e, t) {
                        this._eventEmitter.dispatchEvent(new $e.Nu({
                            eventString: e,
                            allowClickToReconnect: t
                        }))
                    }
                    _onWebRtcConnecting() {
                        this._eventEmitter.dispatchEvent(new $e.Ys)
                    }
                    _onWebRtcConnected() {
                        this._eventEmitter.dispatchEvent(new $e.d4)
                    }
                    _onWebRtcFailed() {
                        this._eventEmitter.dispatchEvent(new $e.tv)
                    }
                    _onVideoInitialized() {
                        this._eventEmitter.dispatchEvent(new $e.Qy), this._videoStartTime = Date.now()
                    }
                    _onLatencyTestResult(e) {

                        const row = [//jose
                            new Date().toISOString(),
                            e.networkLatency,
                            e.encodeLatency,
                            e.CaptureToSendMs,
                            e.endToEndLatency,
                            e.captureToSendLatencyMs
                        ];
                        latencyLog.push(row);
                        this._eventEmitter.dispatchEvent(new $e.Cc({
                            latencyTimings: e
                        }))
                    }
                    _onDataChannelLatencyTestResponse(e) {
                        this._eventEmitter.dispatchEvent(new $e.Fh({
                            response: e
                        }))
                    }
                    _onVideoStats(e) {
                        this._videoStartTime && void 0 !== this._videoStartTime || (this._videoStartTime = Date.now()), e.handleSessionStatistics(this._videoStartTime, this._inputController, this._webRtcController.videoAvgQp), this._eventEmitter.dispatchEvent(new $e.d_({
                            aggregatedStats: e
                        }))
                    }
                    _onVideoEncoderAvgQP(e) {
                        this._eventEmitter.dispatchEvent(new $e.x1({
                            avgQP: e
                        }))
                    }
                    _onInitialSettings(e) {
                        var t;
                        this._eventEmitter.dispatchEvent(new $e.EG({
                            settings: e
                        })), e.PixelStreamingSettings && (this.allowConsoleCommands = null !== (t = e.PixelStreamingSettings.AllowPixelStreamingCommands) && void 0 !== t && t, !1 === this.allowConsoleCommands && a.Vy.Info("-AllowPixelStreamingCommands=false, sending arbitrary console commands from browser to UE is disabled."));
                        const n = this.config.useUrlParams,
                            s = new Ht(window.location.search);
                        a.Vy.Info(`using URL parameters ${n}`), e.EncoderSettings && (e.EncoderSettings.MinQP && (this.config.setNumericSetting(Qe.k$.MinQP, n && s.has(Qe.k$.MinQP) ? Number.parseFloat(s.get(Qe.k$.MinQP)) : e.EncoderSettings.MinQP || 0), this.config.setNumericSetting(Qe.k$.MaxQP, n && s.has(Qe.k$.MaxQP) ? Number.parseFloat(s.get(Qe.k$.MaxQP)) : e.EncoderSettings.MaxQP || 51)), e.EncoderSettings.MinQuality && (this.config.setNumericSetting(Qe.k$.MinQuality, n && s.has(Qe.k$.MinQuality) ? Number.parseFloat(s.get(Qe.k$.MinQuality)) : e.EncoderSettings.MinQuality || 0), this.config.setNumericSetting(Qe.k$.MaxQuality, n && s.has(Qe.k$.MaxQuality) ? Number.parseFloat(s.get(Qe.k$.MaxQuality)) : e.EncoderSettings.MaxQuality || 100)), n && (s.has(Qe.k$.CompatQualityMin) && this.config.setNumericSetting(Qe.k$.CompatQualityMin, Number.parseFloat(s.get(Qe.k$.CompatQualityMin))), s.has(Qe.k$.CompatQualityMax) && this.config.setNumericSetting(Qe.k$.CompatQualityMax, Number.parseFloat(s.get(Qe.k$.CompatQualityMax))))), e.WebRTCSettings && (this.config.setNumericSetting(Qe.k$.WebRTCMinBitrate, n && s.has(Qe.k$.WebRTCMinBitrate) ? Number.parseFloat(s.get(Qe.k$.WebRTCMinBitrate)) : e.WebRTCSettings.MinBitrate / 1e3), this.config.setNumericSetting(Qe.k$.WebRTCMaxBitrate, n && s.has(Qe.k$.WebRTCMaxBitrate) ? Number.parseFloat(s.get(Qe.k$.WebRTCMaxBitrate)) : e.WebRTCSettings.MaxBitrate / 1e3), this.config.setNumericSetting(Qe.k$.WebRTCFPS, n && s.has(Qe.k$.WebRTCFPS) ? Number.parseFloat(s.get(Qe.k$.WebRTCFPS)) : e.WebRTCSettings.FPS))
                    }
                    _onQualityControlOwnership(e) {
                        this.config.setFlagEnabled(Qe.iI.IsQualityController, e)
                    }
                    _onPlayerCount(e) {
                        this._eventEmitter.dispatchEvent(new $e.d2({
                            count: e
                        }))
                    }
                    _onSubscribeFailed(e) {
                        this._eventEmitter.dispatchEvent(new $e._h({
                            message: e
                        }))
                    }
                    _setupWebRtcTCPRelayDetection(e) {
                        const t = e.data.aggregatedStats.getActiveCandidatePair();
                        if (null != t) {
                            const n = e.data.aggregatedStats.localCandidates.find((e => e.id == t.localCandidateId), null);
                            null != n && "relay" == n.candidateType && "tcp" == n.relayProtocol && this._eventEmitter.dispatchEvent(new $e.KB), this._eventEmitter.removeEventListener("statsReceived", this._setupWebRtcTCPRelayDetection)
                        }
                    }
                    requestLatencyTest() {
                        return !!this._webRtcController.videoPlayer.isVideoReady() && (this._webRtcController.sendLatencyTest(), !0)
                    }
                    requestDataChannelLatencyTest(e) {
                        return !!this._webRtcController.videoPlayer.isVideoReady() && (this._dataChannelLatencyTestController || (this._dataChannelLatencyTestController = new Zt(this._webRtcController.sendDataChannelLatencyTest.bind(this._webRtcController), (e => {
                            this._eventEmitter.dispatchEvent(new $e.L7({
                                result: e
                            }))
                        })), this.addEventListener("dataChannelLatencyTestResponse", (({
                            data: {
                                response: e
                            }
                        }) => {
                            this._dataChannelLatencyTestController.receive(e)
                        }))), this._dataChannelLatencyTestController.start(e))
                    }
                    requestShowFps() {
                        return !!this._webRtcController.videoPlayer.isVideoReady() && (this._webRtcController.sendShowFps(), !0)
                    }
                    requestIframe() {
                        return !!this._webRtcController.videoPlayer.isVideoReady() && (this._webRtcController.sendIframeRequest(), !0)
                    }
                    emitUIInteraction(e) {
                        return !!this._webRtcController.videoPlayer.isVideoReady() && (this._webRtcController.emitUIInteraction(e), !0)
                    }
                    emitCommand(e) {
                        return !!this._webRtcController.videoPlayer.isVideoReady() && (!(!this.allowConsoleCommands && "ConsoleCommand" in e) && (this._webRtcController.emitCommand(e), !0))
                    }
                    emitConsoleCommand(e) {
                        return !(!this.allowConsoleCommands || !this._webRtcController.videoPlayer.isVideoReady()) && (this._webRtcController.emitConsoleCommand(e), !0)
                    }
                    sendTextboxEntry(e) {
                        return !!this._webRtcController.videoPlayer.isVideoReady() && (this._webRtcController.sendTextboxEntry(e), !0)
                    }
                    addResponseEventListener(e, t) {
                        this._webRtcController.responseController.addResponseEventListener(e, t)
                    }
                    removeResponseEventListener(e) {
                        this._webRtcController.responseController.removeResponseEventListener(e)
                    }
                    dispatchEvent(e) {
                        return this._eventEmitter.dispatchEvent(e)
                    }
                    addEventListener(e, t) {
                        this._eventEmitter.addEventListener(e, t)
                    }
                    removeEventListener(e, t) {
                        this._eventEmitter.removeEventListener(e, t)
                    }
                    toggleXR() {
                        this.webXrController.xrClicked()
                    }
                    setSignallingUrlBuilder(e) {
                        this._webRtcController.signallingUrlBuilder = e
                    }
                    get webRtcController() {
                        return this._webRtcController
                    }
                    get signallingProtocol() {
                        return this._webRtcController.protocol
                    }
                    get webXrController() {
                        return this._webXrController
                    }
                    registerMessageHandler(e, t, n) {
                        t !== Lt.FromStreamer || void 0 !== n ? t === Lt.ToStreamer && void 0 === n ? this._webRtcController.streamMessageController.registerMessageHandler(t, e, (t => this._webRtcController.sendMessageController.sendMessageToStreamer(e, t))) : this._webRtcController.streamMessageController.registerMessageHandler(t, e, (e => n(e))) : a.Vy.Warning(`Unable to register an undefined handler for ${e}`)
                    }
                    get toStreamerHandlers() {
                        return this._webRtcController.streamMessageController.toStreamerHandlers
                    }
                    isReconnecting() {
                        return this._webRtcController.isReconnecting
                    }
                }
                class tn {}
                var nn = n(753),
                    sn = n.n(nn);
                class rn extends c {
                    constructor(e) {
                        super(), this.WS_OPEN_STATE = 1, e instanceof sn() ? (this.webSocket = e, this.setupSocketHandlers(), this.emit("open")) : e && (this.protocols = e)
                    }
                    sendMessage(e) {
                        this.webSocket && this.webSocket.send(e)
                    }
                    connect(e) {
                        return this.webSocket = new(sn())(e, this.protocols), this.setupSocketHandlers(), !0
                    }
                    disconnect(e, t) {
                        this.webSocket && this.webSocket.close(e, t)
                    }
                    isConnected() {
                        return !!this.webSocket && this.webSocket.readyState != sn().CLOSED
                    }
                    handleOnMessage(e) {
                        this.onMessage && this.onMessage(e.data)
                    }
                    handleOnOpen(e) {
                        this.emit("open", e)
                    }
                    handleOnError(e) {
                        this.emit("error", e)
                    }
                    handleOnClose(e) {
                        this.emit("close", e)
                    }
                    close() {
                        var e;
                        null === (e = this.webSocket) || void 0 === e || e.close()
                    }
                    setupSocketHandlers() {
                        this.webSocket && (this.webSocket.addEventListener("open", this.handleOnOpen.bind(this)), this.webSocket.addEventListener("error", this.handleOnError.bind(this)), this.webSocket.addEventListener("close", this.handleOnClose.bind(this)), this.webSocket.addEventListener("message", this.handleOnMessage.bind(this)))
                    }
                }
            },
            359: (e, t, n) => {
                n.d(t, {
                    R: () => l
                });
                var s = n(879),
                    i = n(945);
                class r {
                    constructor(e) {
                        this.toStreamerMessagesProvider = e, this.controllers = []
                    }
                    updateStatus(e, t, n) {
                        if (e.gamepad) {
                            const s = t.getPose(e.gripSpace, n);
                            if (!s) return;
                            let r = 0;
                            e.profiles.includes("htc-vive") ? r = 1 : e.profiles.includes("oculus-touch") && (r = 2), this.toStreamerMessagesProvider.toStreamerHandlers.get("XRSystem")([r]);
                            let o = 2;
                            switch (e.handedness) {
                                case "left":
                                    o = 0;
                                    break;
                                case "right":
                                    o = 1
                            }
                            const a = s.transform.matrix,
                                l = [];
                            for (let e = 0; e < 16; e++) l[e] = new Float32Array([a[e]])[0];
                            this.toStreamerMessagesProvider.toStreamerHandlers.get("XRControllerTransform")([l[0], l[4], l[8], l[12], l[1], l[5], l[9], l[13], l[2], l[6], l[10], l[14], l[3], l[7], l[11], l[15], o]), void 0 === this.controllers[o] && (this.controllers[o] = {
                                prevState: void 0,
                                currentState: void 0,
                                id: void 0
                            }, this.controllers[o].prevState = (0, i.L)(e.gamepad)), this.controllers[o].currentState = (0, i.L)(e.gamepad);
                            const c = this.controllers[o],
                                d = c.currentState,
                                h = c.prevState;
                            for (let e = 0; e < d.buttons.length; e++) {
                                const t = d.buttons[e],
                                    n = h.buttons[e];
                                if (t.pressed) {
                                    const s = n.pressed ? 1 : 0;
                                    this.toStreamerMessagesProvider.toStreamerHandlers.get("XRButtonPressed")([o, e, s, t.value])
                                } else n.pressed && this.toStreamerMessagesProvider.toStreamerHandlers.get("XRButtonReleased")([o, e, 0]);
                                if (t.touched) {
                                    const t = n.touched ? 1 : 0;
                                    this.toStreamerMessagesProvider.toStreamerHandlers.get("XRButtonTouched")([o, e, t])
                                } else n.touched && this.toStreamerMessagesProvider.toStreamerHandlers.get("XRButtonTouchReleased")([o, e, 0])
                            }
                            for (let e = 0; e < d.axes.length; e++) {
                                const t = d.axes[e];
                                t != h.axes[e] && this.toStreamerMessagesProvider.toStreamerHandlers.get("XRAnalog")([o, e, t])
                            }
                            this.controllers[o].prevState = d
                        }
                    }
                }
                var o = n(656),
                    a = n(442);
                class l {
                    constructor(e) {
                        this.xrViewerPose = null, this.EPSILON = 1e-7, this.videoTexture = null, this.prevVideoWidth = 0, this.prevVideoHeight = 0, this.leftView = null, this.rightView = null, this.lastSentLeftEyeProj = null, this.lastSentRightEyeProj = null, this.lastSentRelativeLeftEyePos = null, this.lastSentRelativeRightEyePos = null, this.xrSession = null, this.webRtcController = e, this.xrGamepadController = new r(this.webRtcController.streamMessageController), this.onSessionEnded = new EventTarget, this.onSessionStarted = new EventTarget, this.onFrame = new EventTarget
                    }
                    xrClicked() {
                        if (this.xrSession) this.xrSession.end();
                        else {
                            if (!navigator.xr) return void s.Vy.Error("This browser does not support XR.");
                            navigator.xr.requestSession("immersive-vr", {
                                optionalFeatures: []
                            }).then((e => {
                                this.onXrSessionStarted(e)
                            }))
                        }
                    }
                    onXrSessionEnded() {
                        s.Vy.Info("XR Session ended"), this.xrSession = null, this.onSessionEnded.dispatchEvent(new Event("xrSessionEnded"))
                    }
                    initGL() {
                        if (this.gl) return;
                        const e = document.createElement("canvas");
                        this.gl = e.getContext("webgl2", {
                            xrCompatible: !0
                        }), this.gl.clearColor(0, 0, 0, 1)
                    }
                    initShaders() {
                        const e = this.gl.createShader(this.gl.VERTEX_SHADER);
                        this.gl.shaderSource(e, "\n        attribute vec2 a_position;\n        attribute vec2 a_texCoord;\n\n        // varyings\n        varying vec2 v_texCoord;\n\n        void main() {\n           gl_Position = vec4(a_position.x, a_position.y, 0, 1);\n           // pass the texCoord to the fragment shader\n           // The GPU will interpolate this value between points.\n           v_texCoord = a_texCoord;\n        }\n        "), this.gl.compileShader(e);
                        const t = this.gl.createShader(this.gl.FRAGMENT_SHADER);
                        this.gl.shaderSource(t, "\n        precision mediump float;\n\n        // our texture\n        uniform sampler2D u_image;\n\n        // the texCoords passed in from the vertex shader.\n        varying vec2 v_texCoord;\n\n        void main() {\n           gl_FragColor = texture2D(u_image, v_texCoord);\n        }\n        "), this.gl.compileShader(t);
                        const n = this.gl.createProgram();
                        this.gl.attachShader(n, e), this.gl.attachShader(n, t), this.gl.linkProgram(n), this.gl.useProgram(n), this.positionLocation = this.gl.getAttribLocation(n, "a_position"), this.texcoordLocation = this.gl.getAttribLocation(n, "a_texCoord")
                    }
                    updateVideoTexture() {
                        this.videoTexture || (this.videoTexture = this.gl.createTexture(), this.gl.bindTexture(this.gl.TEXTURE_2D, this.videoTexture), this.gl.texParameteri(this.gl.TEXTURE_2D, this.gl.TEXTURE_WRAP_S, this.gl.CLAMP_TO_EDGE), this.gl.texParameteri(this.gl.TEXTURE_2D, this.gl.TEXTURE_WRAP_T, this.gl.CLAMP_TO_EDGE), this.gl.texParameteri(this.gl.TEXTURE_2D, this.gl.TEXTURE_MIN_FILTER, this.gl.LINEAR), this.gl.texParameteri(this.gl.TEXTURE_2D, this.gl.TEXTURE_MAG_FILTER, this.gl.LINEAR));
                        const e = this.webRtcController.videoPlayer.getVideoElement().videoHeight,
                            t = this.webRtcController.videoPlayer.getVideoElement().videoWidth;
                        this.prevVideoHeight != e || this.prevVideoWidth != t ? this.gl.texImage2D(this.gl.TEXTURE_2D, 0, this.gl.RGBA, t, e, 0, this.gl.RGBA, this.gl.UNSIGNED_BYTE, this.webRtcController.videoPlayer.getVideoElement()) : this.gl.texSubImage2D(this.gl.TEXTURE_2D, 0, 0, 0, t, e, this.gl.RGBA, this.gl.UNSIGNED_BYTE, this.webRtcController.videoPlayer.getVideoElement()), this.prevVideoHeight = e, this.prevVideoWidth = t
                    }
                    initBuffers() {
                        this.positionBuffer = this.gl.createBuffer(), this.gl.bindBuffer(this.gl.ARRAY_BUFFER, this.positionBuffer), this.gl.enableVertexAttribArray(this.positionLocation), this.gl.bufferData(this.gl.ARRAY_BUFFER, new Float32Array([-1, 1, 1, 1, -1, -1, -1, -1, 1, 1, 1, -1]), this.gl.STATIC_DRAW), this.gl.vertexAttribPointer(this.positionLocation, 2, this.gl.FLOAT, !1, 0, 0), this.texcoordBuffer = this.gl.createBuffer(), this.gl.bindBuffer(this.gl.ARRAY_BUFFER, this.texcoordBuffer), this.gl.enableVertexAttribArray(this.texcoordLocation), this.gl.bufferData(this.gl.ARRAY_BUFFER, new Float32Array([0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1]), this.gl.STATIC_DRAW), this.gl.vertexAttribPointer(this.texcoordLocation, 2, this.gl.FLOAT, !1, 0, 0)
                    }
                    onXrSessionStarted(e) {
                        s.Vy.Info("XR Session started"), this.xrSession = e, this.xrSession.addEventListener("end", (() => {
                            this.onXrSessionEnded()
                        })), this.initGL(), this.initShaders(), this.initBuffers(), e.requestReferenceSpace("local").then((t => {
                            if (this.xrRefSpace = t, this.xrSession.updateRenderState({
                                    baseLayer: new XRWebGLLayer(this.xrSession, this.gl)
                                }), this.xrSession.supportedFrameRates)
                                for (const t of this.xrSession.supportedFrameRates) 90 == t && e.updateTargetFrameRate(90);
                            this.xrSession.requestAnimationFrame(this.onXrFrame.bind(this))
                        })), this.onSessionStarted.dispatchEvent(new Event("xrSessionStarted"))
                    }
                    areArraysEqual(e, t) {
                        return e.length === t.length && e.every(((e, n) => Math.abs(e - t[n]) <= this.EPSILON))
                    }
                    arePointsEqual(e, t) {
                        return Math.abs(e.x - t.x) >= this.EPSILON && Math.abs(e.y - t.y) >= this.EPSILON && Math.abs(e.z - t.z) >= this.EPSILON
                    }
                    sendXRDataToUE() {
                        if (null == this.leftView || null == this.rightView) return;
                        let e = null == this.lastSentLeftEyeProj || null == this.lastSentRightEyeProj || null == this.lastSentRelativeLeftEyePos || null == this.lastSentRelativeRightEyePos;
                        const t = this.leftView.transform.matrix,
                            n = this.leftView.projectionMatrix,
                            s = this.rightView.transform.matrix,
                            i = this.rightView.projectionMatrix,
                            r = this.xrViewerPose.transform.matrix;
                        if (!e && null != this.lastSentLeftEyeProj && null != this.lastSentRightEyeProj) {
                            const t = this.areArraysEqual(n, this.lastSentLeftEyeProj),
                                s = this.areArraysEqual(i, this.lastSentRightEyeProj);
                            e = 0 == t || 0 == s
                        }
                        const o = new DOMPointReadOnly(this.leftView.transform.position.x - this.xrViewerPose.transform.position.x, this.leftView.transform.position.y - this.xrViewerPose.transform.position.y, this.leftView.transform.position.z - this.xrViewerPose.transform.position.z, 1),
                            a = new DOMPointReadOnly(this.leftView.transform.position.x - this.xrViewerPose.transform.position.x, this.leftView.transform.position.y - this.xrViewerPose.transform.position.y, this.leftView.transform.position.z - this.xrViewerPose.transform.position.z, 1);
                        if (!e && null != this.lastSentRelativeLeftEyePos && null != this.lastSentRelativeRightEyePos) {
                            const t = this.arePointsEqual(o, this.lastSentRelativeLeftEyePos),
                                n = this.arePointsEqual(a, this.lastSentRelativeRightEyePos);
                            e = 0 == t || 0 == n
                        }
                        e ? (this.webRtcController.streamMessageController.toStreamerHandlers.get("XREyeViews")([t[0], t[4], t[8], t[12], t[1], t[5], t[9], t[13], t[2], t[6], t[10], t[14], t[3], t[7], t[11], t[15], n[0], n[4], n[8], n[12], n[1], n[5], n[9], n[13], n[2], n[6], n[10], n[14], n[3], n[7], n[11], n[15], s[0], s[4], s[8], s[12], s[1], s[5], s[9], s[13], s[2], s[6], s[10], s[14], s[3], s[7], s[11], s[15], i[0], i[4], i[8], i[12], i[1], i[5], i[9], i[13], i[2], i[6], i[10], i[14], i[3], i[7], i[11], i[15], r[0], r[4], r[8], r[12], r[1], r[5], r[9], r[13], r[2], r[6], r[10], r[14], r[3], r[7], r[11], r[15]]), this.lastSentLeftEyeProj = n, this.lastSentRightEyeProj = i, this.lastSentRelativeLeftEyePos = o, this.lastSentRelativeRightEyePos = a) : this.webRtcController.streamMessageController.toStreamerHandlers.get("XRHMDTransform")([r[0], r[4], r[8], r[12], r[1], r[5], r[9], r[13], r[2], r[6], r[10], r[14], r[3], r[7], r[11], r[15]])
                    }
                    onXrFrame(e, t) {
                        if (this.xrViewerPose = t.getViewerPose(this.xrRefSpace), this.xrViewerPose) {
                            if (this.updateViews(), null == this.leftView || null == this.rightView) return;
                            this.sendXRDataToUE(), this.updateVideoTexture(), this.render()
                        }
                        this.webRtcController.config.isFlagEnabled(a.iI.XRControllerInput) && this.xrSession.inputSources.forEach(((e, n, s) => {
                            this.xrGamepadController.updateStatus(e, t, this.xrRefSpace)
                        }), this), this.xrSession.requestAnimationFrame(((e, t) => this.onXrFrame(e, t))), this.onFrame.dispatchEvent(new o.qM({
                            time: e,
                            frame: t
                        }))
                    }
                    updateViews() {
                        if (this.xrViewerPose)
                            for (const e of this.xrViewerPose.views) "left" === e.eye ? this.leftView = e : "right" === e.eye && (this.rightView = e)
                    }
                    render() {
                        if (!this.gl) return;
                        const e = this.xrSession.renderState.baseLayer;
                        this.gl.bindFramebuffer(this.gl.FRAMEBUFFER, e.framebuffer), this.gl.viewport(0, 0, e.framebufferWidth, e.framebufferHeight), this.gl.drawArrays(this.gl.TRIANGLES, 0, 6)
                    }
                    static isSessionSupported(e) {
                        return "https:" !== location.protocol && s.Vy.Info("WebXR requires https, if you want WebXR use https."), navigator.xr ? navigator.xr.isSessionSupported(e) : new Promise((() => !1))
                    }
                }
            },
            442: (e, t, n) => {
                n.d(t, {
                    B9: () => g,
                    Bs: () => b,
                    CR: () => h,
                    Ri: () => y,
                    TS: () => v,
                    gw: () => p,
                    iI: () => d,
                    k$: () => u,
                    mY: () => f,
                    tQ: () => m
                });
                var s = n(879),
                    i = n(952),
                    r = n(683),
                    o = n(613),
                    a = n(671),
                    l = n(656),
                    c = n(171);
                class d {}
                d.AutoConnect = "AutoConnect", d.AutoPlayVideo = "AutoPlayVideo", d.AFKDetection = "TimeoutIfIdle", d.HoveringMouseMode = "HoveringMouse", d.ForceMonoAudio = "ForceMonoAudio", d.ForceTURN = "ForceTURN", d.FakeMouseWithTouches = "FakeMouseWithTouches", d.IsQualityController = "ControlsQuality", d.MatchViewportResolution = "MatchViewportRes", d.StartVideoMuted = "StartVideoMuted", d.SuppressBrowserKeys = "SuppressBrowserKeys", d.UseMic = "UseMic", d.UseModalForTextInput = "UseModalForTextInput", d.UseCamera = "UseCamera", d.KeyboardInput = "KeyboardInput", d.MouseInput = "MouseInput", d.TouchInput = "TouchInput", d.GamepadInput = "GamepadInput", d.XRControllerInput = "XRControllerInput", d.WaitForStreamer = "WaitForStreamer", d.HideUI = "HideUI", d.EnableCaptureTimeExt = "EnableCaptureTimeExt";
                const h = e => Object.getOwnPropertyNames(d).some((t => d[t] === e));
                class u {}
                u.AFKTimeoutSecs = "AFKTimeout", u.AFKCountdownSecs = "AFKCountdown", u.MinQP = "MinQP", u.MaxQP = "MaxQP", u.MinQuality = "MinQuality", u.MaxQuality = "MaxQuality", u.CompatQualityMin = "CompatQualityMin", u.CompatQualityMax = "CompatQualityMax", u.WebRTCFPS = "WebRTCFPS", u.WebRTCMinBitrate = "WebRTCMinBitrate", u.WebRTCMaxBitrate = "WebRTCMaxBitrate", u.MaxReconnectAttempts = "MaxReconnectAttempts", u.StreamerAutoJoinInterval = "StreamerAutoJoinInterval", u.KeepaliveDelay = "KeepaliveDelay";
                const m = e => Object.getOwnPropertyNames(u).some((t => u[t] === e));
                class p {}
                p.SignallingServerUrl = "ss";
                const g = e => Object.getOwnPropertyNames(p).some((t => p[t] === e));
                class f {}
                f.PreferredCodec = "PreferredCodec", f.StreamerId = "StreamerId", f.PreferredQuality = "PreferredQuality";
                const y = e => Object.getOwnPropertyNames(f).some((t => f[t] === e));
                class v {
                    constructor(e = {}) {
                        this.flags = new Map, this.numericParameters = new Map, this.textParameters = new Map, this.optionParameters = new Map;
                        const {
                            initialSettings: t,
                            useUrlParams: n,
                            webSocketProtocols: s
                        } = e;
                        this._useUrlParams = !!n, this._webSocketProtocols = s, this.populateDefaultSettings(this._useUrlParams, t)
                    }
                    get useUrlParams() {
                        return this._useUrlParams
                    }
                    get webSocketProtocols() {
                        return this._webSocketProtocols
                    }
                    populateDefaultSettings(e, t) {
                        this.textParameters.set(p.SignallingServerUrl, new o.c(p.SignallingServerUrl, "Signalling url", "Url of the signalling server", t && Object.prototype.hasOwnProperty.call(t, p.SignallingServerUrl) ? t[p.SignallingServerUrl] : ("https:" === location.protocol ? "wss://" : "ws://") + window.location.hostname + ("80" === window.location.port || "" === window.location.port ? "" : `:${window.location.port}`), e)), this.optionParameters.set(f.StreamerId, new a.G(f.StreamerId, "Streamer ID", "The ID of the streamer to stream.", t && Object.prototype.hasOwnProperty.call(t, f.StreamerId) ? t[f.StreamerId] : "", t && Object.prototype.hasOwnProperty.call(t, f.StreamerId) ? [t[f.StreamerId]] : void 0, e));
                        const n = function(e) {
                            const t = c.C.getSupportedVideoCodecs();
                            if (t.includes(e)) return e;
                            for (const n of t)
                                if (n.startsWith(e)) return n;
                            return e
                        };
                        this.optionParameters.set(f.PreferredCodec, new a.G(f.PreferredCodec, "Preferred Codec", "The preferred codec to be used during codec negotiation", t && Object.prototype.hasOwnProperty.call(t, f.PreferredCodec) ? n(t[f.PreferredCodec]) : function() {
                            const e = c.C.getSupportedVideoCodecs();
                            if (1 == e.length) return e[0];
                            if (e.length > 0) {
                                const t = e[0];
                                for (const t of e)
                                    if (t.startsWith("H264")) return t;
                                return t
                            }
                            return s.Vy.Error("Could not find any reasonable video codec to assign as a default."), ""
                        }(), c.C.getSupportedVideoCodecs(), e, n)), this.optionParameters.set(f.PreferredQuality, new a.G(f.PreferredQuality, "Preferred Quality", "The preferred quality of the stream (only applicable when using the SFU)", t && Object.prototype.hasOwnProperty.call(t, f.PreferredQuality) ? t[f.PreferredQuality] : "Default", ["Default"], e)), this.flags.set(d.AutoConnect, new i.T(d.AutoConnect, "Auto connect to stream", "Whether we should attempt to auto connect to the signalling server or show a click to start prompt.", !(!t || !Object.prototype.hasOwnProperty.call(t, d.AutoConnect)) && t[d.AutoConnect], e)), this.flags.set(d.AutoPlayVideo, new i.T(d.AutoPlayVideo, "Auto play video", "When video is ready automatically start playing it as opposed to showing a play button.", !t || !Object.prototype.hasOwnProperty.call(t, d.AutoPlayVideo) || t[d.AutoPlayVideo], e)), this.flags.set(d.UseMic, new i.T(d.UseMic, "Use microphone", "Make browser request microphone access and open an input audio track.", !(!t || !Object.prototype.hasOwnProperty.call(t, d.UseMic)) && t[d.UseMic], e)), this.flags.set(d.UseModalForTextInput, new i.T(d.UseModalForTextInput, "Use modal for text input", "When entering input into a streamed UE text widget, use an input modal.", !t || !Object.prototype.hasOwnProperty.call(t, d.UseModalForTextInput) || t[d.UseModalForTextInput], e)), this.flags.set(d.UseCamera, new i.T(d.UseCamera, "Use webcam", "Make browser request webcam access and open a input video track.", !(!t || !Object.prototype.hasOwnProperty.call(t, d.UseCamera)) && t[d.UseCamera], e)), this.flags.set(d.StartVideoMuted, new i.T(d.StartVideoMuted, "Start video muted", "Video will start muted if true.", !(!t || !Object.prototype.hasOwnProperty.call(t, d.StartVideoMuted)) && t[d.StartVideoMuted], e)), this.flags.set(d.SuppressBrowserKeys, new i.T(d.SuppressBrowserKeys, "Suppress browser keys", "Suppress certain browser keys that we use in UE, for example F5 to show shader complexity instead of refresh the page.", !t || !Object.prototype.hasOwnProperty.call(t, d.SuppressBrowserKeys) || t[d.SuppressBrowserKeys], e)), this.flags.set(d.IsQualityController, new i.T(d.IsQualityController, "Is quality controller?", "True if this peer controls stream quality", !t || !Object.prototype.hasOwnProperty.call(t, d.IsQualityController) || t[d.IsQualityController], e)), this.flags.set(d.ForceMonoAudio, new i.T(d.ForceMonoAudio, "Force mono audio", "Force browser to request mono audio in the SDP", !(!t || !Object.prototype.hasOwnProperty.call(t, d.ForceMonoAudio)) && t[d.ForceMonoAudio], e)), this.flags.set(d.ForceTURN, new i.T(d.ForceTURN, "Force TURN", "Only generate TURN/Relayed ICE candidates.", !(!t || !Object.prototype.hasOwnProperty.call(t, d.ForceTURN)) && t[d.ForceTURN], e)), this.flags.set(d.AFKDetection, new i.T(d.AFKDetection, "AFK if idle", "Timeout the experience if user is AFK for a period.", !(!t || !Object.prototype.hasOwnProperty.call(t, d.AFKDetection)) && t[d.AFKDetection], e)), this.flags.set(d.MatchViewportResolution, new i.T(d.MatchViewportResolution, "Match viewport resolution", "Pixel Streaming will be instructed to dynamically resize the video stream to match the size of the video element.", !(!t || !Object.prototype.hasOwnProperty.call(t, d.MatchViewportResolution)) && t[d.MatchViewportResolution], e)), this.flags.set(d.HoveringMouseMode, new i.T(d.HoveringMouseMode, "Control Scheme: Locked Mouse", "Either locked mouse, where the pointer is consumed by the video and locked to it, or hovering mouse, where the mouse is not consumed.", !(!t || !Object.prototype.hasOwnProperty.call(t, d.HoveringMouseMode)) && t[d.HoveringMouseMode], e, ((e, t) => {
                            t.label = `Control Scheme: ${e?"Hovering":"Locked"} Mouse`
                        }))), this.flags.set(d.FakeMouseWithTouches, new i.T(d.FakeMouseWithTouches, "Fake mouse with touches", "A single finger touch is converted into a mouse event. This allows a non-touch application to be controlled partially via a touch device.", !(!t || !Object.prototype.hasOwnProperty.call(t, d.FakeMouseWithTouches)) && t[d.FakeMouseWithTouches], e)), this.flags.set(d.KeyboardInput, new i.T(d.KeyboardInput, "Keyboard input", "If enabled, send keyboard events to streamer", !t || !Object.prototype.hasOwnProperty.call(t, d.KeyboardInput) || t[d.KeyboardInput], e)), this.flags.set(d.MouseInput, new i.T(d.MouseInput, "Mouse input", "If enabled, send mouse events to streamer", !t || !Object.prototype.hasOwnProperty.call(t, d.MouseInput) || t[d.MouseInput], e)), this.flags.set(d.TouchInput, new i.T(d.TouchInput, "Touch input", "If enabled, send touch events to streamer", !t || !Object.prototype.hasOwnProperty.call(t, d.TouchInput) || t[d.TouchInput], e)), this.flags.set(d.GamepadInput, new i.T(d.GamepadInput, "Gamepad input", "If enabled, send gamepad events to streamer", !t || !Object.prototype.hasOwnProperty.call(t, d.GamepadInput) || t[d.GamepadInput], e)), this.flags.set(d.XRControllerInput, new i.T(d.XRControllerInput, "XR controller input", "If enabled, send XR controller events to streamer", !t || !Object.prototype.hasOwnProperty.call(t, d.XRControllerInput) || t[d.XRControllerInput], e)), this.flags.set(d.WaitForStreamer, new i.T(d.WaitForStreamer, "Wait for streamer", "Will continue trying to connect to the first streamer available.", !t || !Object.prototype.hasOwnProperty.call(t, d.WaitForStreamer) || t[d.WaitForStreamer], e)), this.flags.set(d.HideUI, new i.T(d.HideUI, "Hide the UI overlay", "Will hide all UI overlay details", !(!t || !Object.prototype.hasOwnProperty.call(t, d.HideUI)) && t[d.HideUI], e)), this.flags.set(d.EnableCaptureTimeExt, new i.T(d.EnableCaptureTimeExt, "Enable abs-capture-time", "Enables the abs-capture-time RTP header extension", !(!t || !Object.prototype.hasOwnProperty.call(t, d.EnableCaptureTimeExt)) && t[d.EnableCaptureTimeExt], e)), this.numericParameters.set(u.AFKTimeoutSecs, new r.U(u.AFKTimeoutSecs, "AFK timeout", "The time (in seconds) it takes for the application to time out if AFK timeout is enabled.", 0, null, t && Object.prototype.hasOwnProperty.call(t, u.AFKTimeoutSecs) ? t[u.AFKTimeoutSecs] : 120, e)), this.numericParameters.set(u.AFKCountdownSecs, new r.U(u.AFKCountdownSecs, "AFK countdown", "The time (in seconds) for a user to respond before the stream is ended after an AFK timeout.", 10, null, 10, e)), this.numericParameters.set(u.MaxReconnectAttempts, new r.U(u.MaxReconnectAttempts, "Max Reconnects", "Maximum number of reconnects the application will attempt when a streamer disconnects.", 0, 999, t && Object.prototype.hasOwnProperty.call(t, u.MaxReconnectAttempts) ? t[u.MaxReconnectAttempts] : 3, e)), this.numericParameters.set(u.MinQP, new r.U(u.MinQP, "Min QP", "The lower bound for the quantization parameter (QP) of the encoder. 0 = Best quality, 51 = worst quality.", 0, 51, t && Object.prototype.hasOwnProperty.call(t, u.MinQP) ? t[u.MinQP] : 0, e)), this.numericParameters.set(u.MaxQP, new r.U(u.MaxQP, "Max QP", "The upper bound for the quantization parameter (QP) of the encoder. 0 = Best quality, 51 = worst quality.", 0, 51, t && Object.prototype.hasOwnProperty.call(t, u.MaxQP) ? t[u.MaxQP] : 51, e)), this.numericParameters.set(u.MinQuality, new r.U(u.MinQuality, "Min Quality", "The lower bound for the quality factor of the encoder. 0 = Worst quality, 100 = Best quality.", 0, 100, t && Object.prototype.hasOwnProperty.call(t, u.MinQuality) ? t[u.MinQuality] : 0, e)), this.numericParameters.set(u.MaxQuality, new r.U(u.MaxQuality, "Max Quality", "The upper bound for the quality factor of the encoder. 0 = Worst quality, 100 = Best quality.", 0, 100, t && Object.prototype.hasOwnProperty.call(t, u.MaxQuality) ? t[u.MaxQuality] : 100, e)), this.numericParameters.set(u.CompatQualityMin, new r.U(u.CompatQualityMin, "Min Quality", "The lower bound for encoding quality. 0 = Worst, 100 = Best.", 0, 100, t && Object.prototype.hasOwnProperty.call(t, u.CompatQualityMin) ? t[u.CompatQualityMin] : 0, e)), this.numericParameters.set(u.CompatQualityMax, new r.U(u.CompatQualityMax, "Max Quality", "The upper bound for encoding quality. 0 = Worst, 100 = Best.", 0, 100, t && Object.prototype.hasOwnProperty.call(t, u.CompatQualityMax) ? t[u.CompatQualityMax] : 100, e)), this.numericParameters.set(u.WebRTCFPS, new r.U(u.WebRTCFPS, "Max FPS", "The maximum FPS that WebRTC will try to transmit frames at.", 1, 999, t && Object.prototype.hasOwnProperty.call(t, u.WebRTCFPS) ? t[u.WebRTCFPS] : 60, e)), this.numericParameters.set(u.WebRTCMinBitrate, new r.U(u.WebRTCMinBitrate, "Min Bitrate (kbps)", "The minimum bitrate that WebRTC should use.", 0, 5e5, t && Object.prototype.hasOwnProperty.call(t, u.WebRTCMinBitrate) ? t[u.WebRTCMinBitrate] : 0, e)), this.numericParameters.set(u.WebRTCMaxBitrate, new r.U(u.WebRTCMaxBitrate, "Max Bitrate (kbps)", "The maximum bitrate that WebRTC should use.", 0, 5e5, t && Object.prototype.hasOwnProperty.call(t, u.WebRTCMaxBitrate) ? t[u.WebRTCMaxBitrate] : 0, e)), this.numericParameters.set(u.StreamerAutoJoinInterval, new r.U(u.StreamerAutoJoinInterval, "Streamer Auto Join Interval (ms)", "Delay between retries when waiting for an available streamer.", 500, 9e5, t && Object.prototype.hasOwnProperty.call(t, u.StreamerAutoJoinInterval) ? t[u.StreamerAutoJoinInterval] : 3e3, e)), this.numericParameters.set(u.KeepaliveDelay, new r.U(u.KeepaliveDelay, "Connection Keepalive delay", "Delay between keepalive pings to the signalling server.", 0, 9e5, t && Object.prototype.hasOwnProperty.call(t, u.KeepaliveDelay) ? t[u.KeepaliveDelay] : 3e4, e))
                    }
                    _addOnNumericSettingChangedListener(e, t) {
                        this.numericParameters.has(e) && this.numericParameters.get(e).addOnChangedListener(t)
                    }
                    _addOnOptionSettingChangedListener(e, t) {
                        this.optionParameters.has(e) && this.optionParameters.get(e).addOnChangedListener(t)
                    }
                    getNumericSettingValue(e) {
                        if (this.numericParameters.has(e)) return this.numericParameters.get(e).number;
                        throw new Error(`There is no numeric setting with the id of ${e}`)
                    }
                    getTextSettingValue(e) {
                        if (this.textParameters.has(e)) return this.textParameters.get(e).value;
                        throw new Error(`There is no numeric setting with the id of ${e}`)
                    }
                    setNumericSetting(e, t) {
                        if (!this.numericParameters.has(e)) throw new Error(`There is no numeric setting with the id of ${e}`);
                        this.numericParameters.get(e).number = t
                    }
                    _addOnSettingChangedListener(e, t) {
                        this.flags.has(e) && (this.flags.get(e).onChange = t)
                    }
                    _addOnTextSettingChangedListener(e, t) {
                        this.textParameters.has(e) && (this.textParameters.get(e).onChange = t)
                    }
                    getSettingOption(e) {
                        return this.optionParameters.get(e)
                    }
                    isFlagEnabled(e) {
                        return this.flags.get(e).flag
                    }
                    setFlagEnabled(e, t) {
                        this.flags.has(e) ? this.flags.get(e).flag = t : s.Vy.Warning(`Cannot toggle flag called ${e} - it does not exist in the Config.flags map.`)
                    }
                    setTextSetting(e, t) {
                        this.textParameters.has(e) ? this.textParameters.get(e).text = t : s.Vy.Warning(`Cannot set text setting called ${e} - it does not exist in the Config.textParameters map.`)
                    }
                    setOptionSettingOptions(e, t) {
                        this.optionParameters.has(e) ? this.optionParameters.get(e).options = t : s.Vy.Warning(`Cannot set text setting called ${e} - it does not exist in the Config.optionParameters map.`)
                    }
                    setOptionSettingValue(e, t) {
                        if (this.optionParameters.has(e)) {
                            const n = this.optionParameters.get(e),
                                s = n.options;
                            s.includes(t) || (s.push(t), n.options = s), n.selected = t
                        } else s.Vy.Warning(`Cannot set text setting called ${e} - it does not exist in the Config.enumParameters map.`)
                    }
                    setFlagLabel(e, t) {
                        this.flags.has(e) ? this.flags.get(e).label = t : s.Vy.Warning(`Cannot set label for flag called ${e} - it does not exist in the Config.flags map.`)
                    }
                    setSettings(e) {
                        for (const t of Object.keys(e)) h(t) ? this.setFlagEnabled(t, e[t]) : m(t) ? this.setNumericSetting(t, e[t]) : g(t) ? this.setTextSetting(t, e[t]) : y(t) && this.setOptionSettingValue(t, e[t])
                    }
                    getSettings() {
                        const e = {};
                        for (const [t, n] of this.flags.entries()) e[t] = n.flag;
                        for (const [t, n] of this.numericParameters.entries()) e[t] = n.number;
                        for (const [t, n] of this.textParameters.entries()) e[t] = n.text;
                        for (const [t, n] of this.optionParameters.entries()) e[t] = n.selected;
                        return e
                    }
                    getFlags() {
                        return Array.from(this.flags.values())
                    }
                    getTextSettings() {
                        return Array.from(this.textParameters.values())
                    }
                    getNumericSettings() {
                        return Array.from(this.numericParameters.values())
                    }
                    getOptionSettings() {
                        return Array.from(this.optionParameters.values())
                    }
                    _registerOnChangeEvents(e) {
                        for (const t of this.flags.keys()) {
                            const n = this.flags.get(t);
                            n && (n.onChangeEmit = t => e.dispatchEvent(new l.Si({
                                id: n.id,
                                type: "flag",
                                value: t,
                                target: n
                            })))
                        }
                        for (const t of this.numericParameters.keys()) {
                            const n = this.numericParameters.get(t);
                            n && (n.onChangeEmit = t => e.dispatchEvent(new l.Si({
                                id: n.id,
                                type: "number",
                                value: t,
                                target: n
                            })))
                        }
                        for (const t of this.textParameters.keys()) {
                            const n = this.textParameters.get(t);
                            n && (n.onChangeEmit = t => e.dispatchEvent(new l.Si({
                                id: n.id,
                                type: "text",
                                value: t,
                                target: n
                            })))
                        }
                        for (const t of this.optionParameters.keys()) {
                            const n = this.optionParameters.get(t);
                            n && (n.onChangeEmit = t => e.dispatchEvent(new l.Si({
                                id: n.id,
                                type: "option",
                                value: t,
                                target: n
                            })))
                        }
                    }
                }
                var b;
                ! function(e) {
                    e[e.LockedMouse = 0] = "LockedMouse", e[e.HoveringMouse = 1] = "HoveringMouse"
                }(b || (b = {}))
            },
            585: e => {
                const t = {
                    generateIdentifier: function() {
                        return Math.random().toString(36).substring(2, 12)
                    }
                };
                t.localCName = t.generateIdentifier(), t.splitLines = function(e) {
                    return e.trim().split("\n").map((e => e.trim()))
                }, t.splitSections = function(e) {
                    return e.split("\nm=").map(((e, t) => (t > 0 ? "m=" + e : e).trim() + "\r\n"))
                }, t.getDescription = function(e) {
                    const n = t.splitSections(e);
                    return n && n[0]
                }, t.getMediaSections = function(e) {
                    const n = t.splitSections(e);
                    return n.shift(), n
                }, t.matchPrefix = function(e, n) {
                    return t.splitLines(e).filter((e => 0 === e.indexOf(n)))
                }, t.parseCandidate = function(e) {
                    let t;
                    t = 0 === e.indexOf("a=candidate:") ? e.substring(12).split(" ") : e.substring(10).split(" ");
                    const n = {
                        foundation: t[0],
                        component: {
                            1: "rtp",
                            2: "rtcp"
                        } [t[1]] || t[1],
                        protocol: t[2].toLowerCase(),
                        priority: parseInt(t[3], 10),
                        ip: t[4],
                        address: t[4],
                        port: parseInt(t[5], 10),
                        type: t[7]
                    };
                    for (let e = 8; e < t.length; e += 2) switch (t[e]) {
                        case "raddr":
                            n.relatedAddress = t[e + 1];
                            break;
                        case "rport":
                            n.relatedPort = parseInt(t[e + 1], 10);
                            break;
                        case "tcptype":
                            n.tcpType = t[e + 1];
                            break;
                        case "ufrag":
                            n.ufrag = t[e + 1], n.usernameFragment = t[e + 1];
                            break;
                        default:
                            void 0 === n[t[e]] && (n[t[e]] = t[e + 1])
                    }
                    return n
                }, t.writeCandidate = function(e) {
                    const t = [];
                    t.push(e.foundation);
                    const n = e.component;
                    "rtp" === n ? t.push(1) : "rtcp" === n ? t.push(2) : t.push(n), t.push(e.protocol.toUpperCase()), t.push(e.priority), t.push(e.address || e.ip), t.push(e.port);
                    const s = e.type;
                    return t.push("typ"), t.push(s), "host" !== s && e.relatedAddress && e.relatedPort && (t.push("raddr"), t.push(e.relatedAddress), t.push("rport"), t.push(e.relatedPort)), e.tcpType && "tcp" === e.protocol.toLowerCase() && (t.push("tcptype"), t.push(e.tcpType)), (e.usernameFragment || e.ufrag) && (t.push("ufrag"), t.push(e.usernameFragment || e.ufrag)), "candidate:" + t.join(" ")
                }, t.parseIceOptions = function(e) {
                    return e.substring(14).split(" ")
                }, t.parseRtpMap = function(e) {
                    let t = e.substring(9).split(" ");
                    const n = {
                        payloadType: parseInt(t.shift(), 10)
                    };
                    return t = t[0].split("/"), n.name = t[0], n.clockRate = parseInt(t[1], 10), n.channels = 3 === t.length ? parseInt(t[2], 10) : 1, n.numChannels = n.channels, n
                }, t.writeRtpMap = function(e) {
                    let t = e.payloadType;
                    void 0 !== e.preferredPayloadType && (t = e.preferredPayloadType);
                    const n = e.channels || e.numChannels || 1;
                    return "a=rtpmap:" + t + " " + e.name + "/" + e.clockRate + (1 !== n ? "/" + n : "") + "\r\n"
                }, t.parseExtmap = function(e) {
                    const t = e.substring(9).split(" ");
                    return {
                        id: parseInt(t[0], 10),
                        direction: t[0].indexOf("/") > 0 ? t[0].split("/")[1] : "sendrecv",
                        uri: t[1],
                        attributes: t.slice(2).join(" ")
                    }
                }, t.writeExtmap = function(e) {
                    return "a=extmap:" + (e.id || e.preferredId) + (e.direction && "sendrecv" !== e.direction ? "/" + e.direction : "") + " " + e.uri + (e.attributes ? " " + e.attributes : "") + "\r\n"
                }, t.parseFmtp = function(e) {
                    const t = {};
                    let n;
                    const s = e.substring(e.indexOf(" ") + 1).split(";");
                    for (let e = 0; e < s.length; e++) n = s[e].trim().split("="), t[n[0].trim()] = n[1];
                    return t
                }, t.writeFmtp = function(e) {
                    let t = "",
                        n = e.payloadType;
                    if (void 0 !== e.preferredPayloadType && (n = e.preferredPayloadType), e.parameters && Object.keys(e.parameters).length) {
                        const s = [];
                        Object.keys(e.parameters).forEach((t => {
                            void 0 !== e.parameters[t] ? s.push(t + "=" + e.parameters[t]) : s.push(t)
                        })), t += "a=fmtp:" + n + " " + s.join(";") + "\r\n"
                    }
                    return t
                }, t.parseRtcpFb = function(e) {
                    const t = e.substring(e.indexOf(" ") + 1).split(" ");
                    return {
                        type: t.shift(),
                        parameter: t.join(" ")
                    }
                }, t.writeRtcpFb = function(e) {
                    let t = "",
                        n = e.payloadType;
                    return void 0 !== e.preferredPayloadType && (n = e.preferredPayloadType), e.rtcpFeedback && e.rtcpFeedback.length && e.rtcpFeedback.forEach((e => {
                        t += "a=rtcp-fb:" + n + " " + e.type + (e.parameter && e.parameter.length ? " " + e.parameter : "") + "\r\n"
                    })), t
                }, t.parseSsrcMedia = function(e) {
                    const t = e.indexOf(" "),
                        n = {
                            ssrc: parseInt(e.substring(7, t), 10)
                        },
                        s = e.indexOf(":", t);
                    return s > -1 ? (n.attribute = e.substring(t + 1, s), n.value = e.substring(s + 1)) : n.attribute = e.substring(t + 1), n
                }, t.parseSsrcGroup = function(e) {
                    const t = e.substring(13).split(" ");
                    return {
                        semantics: t.shift(),
                        ssrcs: t.map((e => parseInt(e, 10)))
                    }
                }, t.getMid = function(e) {
                    const n = t.matchPrefix(e, "a=mid:")[0];
                    if (n) return n.substring(6)
                }, t.parseFingerprint = function(e) {
                    const t = e.substring(14).split(" ");
                    return {
                        algorithm: t[0].toLowerCase(),
                        value: t[1].toUpperCase()
                    }
                }, t.getDtlsParameters = function(e, n) {
                    return {
                        role: "auto",
                        fingerprints: t.matchPrefix(e + n, "a=fingerprint:").map(t.parseFingerprint)
                    }
                }, t.writeDtlsParameters = function(e, t) {
                    let n = "a=setup:" + t + "\r\n";
                    return e.fingerprints.forEach((e => {
                        n += "a=fingerprint:" + e.algorithm + " " + e.value + "\r\n"
                    })), n
                }, t.parseCryptoLine = function(e) {
                    const t = e.substring(9).split(" ");
                    return {
                        tag: parseInt(t[0], 10),
                        cryptoSuite: t[1],
                        keyParams: t[2],
                        sessionParams: t.slice(3)
                    }
                }, t.writeCryptoLine = function(e) {
                    return "a=crypto:" + e.tag + " " + e.cryptoSuite + " " + ("object" == typeof e.keyParams ? t.writeCryptoKeyParams(e.keyParams) : e.keyParams) + (e.sessionParams ? " " + e.sessionParams.join(" ") : "") + "\r\n"
                }, t.parseCryptoKeyParams = function(e) {
                    if (0 !== e.indexOf("inline:")) return null;
                    const t = e.substring(7).split("|");
                    return {
                        keyMethod: "inline",
                        keySalt: t[0],
                        lifeTime: t[1],
                        mkiValue: t[2] ? t[2].split(":")[0] : void 0,
                        mkiLength: t[2] ? t[2].split(":")[1] : void 0
                    }
                }, t.writeCryptoKeyParams = function(e) {
                    return e.keyMethod + ":" + e.keySalt + (e.lifeTime ? "|" + e.lifeTime : "") + (e.mkiValue && e.mkiLength ? "|" + e.mkiValue + ":" + e.mkiLength : "")
                }, t.getCryptoParameters = function(e, n) {
                    return t.matchPrefix(e + n, "a=crypto:").map(t.parseCryptoLine)
                }, t.getIceParameters = function(e, n) {
                    const s = t.matchPrefix(e + n, "a=ice-ufrag:")[0],
                        i = t.matchPrefix(e + n, "a=ice-pwd:")[0];
                    return s && i ? {
                        usernameFragment: s.substring(12),
                        password: i.substring(10)
                    } : null
                }, t.writeIceParameters = function(e) {
                    let t = "a=ice-ufrag:" + e.usernameFragment + "\r\na=ice-pwd:" + e.password + "\r\n";
                    return e.iceLite && (t += "a=ice-lite\r\n"), t
                }, t.parseRtpParameters = function(e) {
                    const n = {
                            codecs: [],
                            headerExtensions: [],
                            fecMechanisms: [],
                            rtcp: []
                        },
                        s = t.splitLines(e)[0].split(" ");
                    n.profile = s[2];
                    for (let i = 3; i < s.length; i++) {
                        const r = s[i],
                            o = t.matchPrefix(e, "a=rtpmap:" + r + " ")[0];
                        if (o) {
                            const s = t.parseRtpMap(o),
                                i = t.matchPrefix(e, "a=fmtp:" + r + " ");
                            switch (s.parameters = i.length ? t.parseFmtp(i[0]) : {}, s.rtcpFeedback = t.matchPrefix(e, "a=rtcp-fb:" + r + " ").map(t.parseRtcpFb), n.codecs.push(s), s.name.toUpperCase()) {
                                case "RED":
                                case "ULPFEC":
                                    n.fecMechanisms.push(s.name.toUpperCase())
                            }
                        }
                    }
                    t.matchPrefix(e, "a=extmap:").forEach((e => {
                        n.headerExtensions.push(t.parseExtmap(e))
                    }));
                    const i = t.matchPrefix(e, "a=rtcp-fb:* ").map(t.parseRtcpFb);
                    return n.codecs.forEach((e => {
                        i.forEach((t => {
                            e.rtcpFeedback.find((e => e.type === t.type && e.parameter === t.parameter)) || e.rtcpFeedback.push(t)
                        }))
                    })), n
                }, t.writeRtpDescription = function(e, n) {
                    let s = "";
                    s += "m=" + e + " ", s += n.codecs.length > 0 ? "9" : "0", s += " " + (n.profile || "UDP/TLS/RTP/SAVPF") + " ", s += n.codecs.map((e => void 0 !== e.preferredPayloadType ? e.preferredPayloadType : e.payloadType)).join(" ") + "\r\n", s += "c=IN IP4 0.0.0.0\r\n", s += "a=rtcp:9 IN IP4 0.0.0.0\r\n", n.codecs.forEach((e => {
                        s += t.writeRtpMap(e), s += t.writeFmtp(e), s += t.writeRtcpFb(e)
                    }));
                    let i = 0;
                    return n.codecs.forEach((e => {
                        e.maxptime > i && (i = e.maxptime)
                    })), i > 0 && (s += "a=maxptime:" + i + "\r\n"), n.headerExtensions && n.headerExtensions.forEach((e => {
                        s += t.writeExtmap(e)
                    })), s
                }, t.parseRtpEncodingParameters = function(e) {
                    const n = [],
                        s = t.parseRtpParameters(e),
                        i = -1 !== s.fecMechanisms.indexOf("RED"),
                        r = -1 !== s.fecMechanisms.indexOf("ULPFEC"),
                        o = t.matchPrefix(e, "a=ssrc:").map((e => t.parseSsrcMedia(e))).filter((e => "cname" === e.attribute)),
                        a = o.length > 0 && o[0].ssrc;
                    let l;
                    const c = t.matchPrefix(e, "a=ssrc-group:FID").map((e => e.substring(17).split(" ").map((e => parseInt(e, 10)))));
                    c.length > 0 && c[0].length > 1 && c[0][0] === a && (l = c[0][1]), s.codecs.forEach((e => {
                        if ("RTX" === e.name.toUpperCase() && e.parameters.apt) {
                            let t = {
                                ssrc: a,
                                codecPayloadType: parseInt(e.parameters.apt, 10)
                            };
                            a && l && (t.rtx = {
                                ssrc: l
                            }), n.push(t), i && (t = JSON.parse(JSON.stringify(t)), t.fec = {
                                ssrc: a,
                                mechanism: r ? "red+ulpfec" : "red"
                            }, n.push(t))
                        }
                    })), 0 === n.length && a && n.push({
                        ssrc: a
                    });
                    let d = t.matchPrefix(e, "b=");
                    return d.length && (d = 0 === d[0].indexOf("b=TIAS:") ? parseInt(d[0].substring(7), 10) : 0 === d[0].indexOf("b=AS:") ? 1e3 * parseInt(d[0].substring(5), 10) * .95 - 16e3 : void 0, n.forEach((e => {
                        e.maxBitrate = d
                    }))), n
                }, t.parseRtcpParameters = function(e) {
                    const n = {},
                        s = t.matchPrefix(e, "a=ssrc:").map((e => t.parseSsrcMedia(e))).filter((e => "cname" === e.attribute))[0];
                    s && (n.cname = s.value, n.ssrc = s.ssrc);
                    const i = t.matchPrefix(e, "a=rtcp-rsize");
                    n.reducedSize = i.length > 0, n.compound = 0 === i.length;
                    const r = t.matchPrefix(e, "a=rtcp-mux");
                    return n.mux = r.length > 0, n
                }, t.writeRtcpParameters = function(e) {
                    let t = "";
                    return e.reducedSize && (t += "a=rtcp-rsize\r\n"), e.mux && (t += "a=rtcp-mux\r\n"), void 0 !== e.ssrc && e.cname && (t += "a=ssrc:" + e.ssrc + " cname:" + e.cname + "\r\n"), t
                }, t.parseMsid = function(e) {
                    let n;
                    const s = t.matchPrefix(e, "a=msid:");
                    if (1 === s.length) return n = s[0].substring(7).split(" "), {
                        stream: n[0],
                        track: n[1]
                    };
                    const i = t.matchPrefix(e, "a=ssrc:").map((e => t.parseSsrcMedia(e))).filter((e => "msid" === e.attribute));
                    return i.length > 0 ? (n = i[0].value.split(" "), {
                        stream: n[0],
                        track: n[1]
                    }) : void 0
                }, t.parseSctpDescription = function(e) {
                    const n = t.parseMLine(e),
                        s = t.matchPrefix(e, "a=max-message-size:");
                    let i;
                    s.length > 0 && (i = parseInt(s[0].substring(19), 10)), isNaN(i) && (i = 65536);
                    const r = t.matchPrefix(e, "a=sctp-port:");
                    if (r.length > 0) return {
                        port: parseInt(r[0].substring(12), 10),
                        protocol: n.fmt,
                        maxMessageSize: i
                    };
                    const o = t.matchPrefix(e, "a=sctpmap:");
                    if (o.length > 0) {
                        const e = o[0].substring(10).split(" ");
                        return {
                            port: parseInt(e[0], 10),
                            protocol: e[1],
                            maxMessageSize: i
                        }
                    }
                }, t.writeSctpDescription = function(e, t) {
                    let n = [];
                    return n = "DTLS/SCTP" !== e.protocol ? ["m=" + e.kind + " 9 " + e.protocol + " " + t.protocol + "\r\n", "c=IN IP4 0.0.0.0\r\n", "a=sctp-port:" + t.port + "\r\n"] : ["m=" + e.kind + " 9 " + e.protocol + " " + t.port + "\r\n", "c=IN IP4 0.0.0.0\r\n", "a=sctpmap:" + t.port + " " + t.protocol + " 65535\r\n"], void 0 !== t.maxMessageSize && n.push("a=max-message-size:" + t.maxMessageSize + "\r\n"), n.join("")
                }, t.generateSessionId = function() {
                    return Math.random().toString().substr(2, 22)
                }, t.writeSessionBoilerplate = function(e, n, s) {
                    let i;
                    const r = void 0 !== n ? n : 2;
                    i = e || t.generateSessionId();
                    return "v=0\r\no=" + (s || "thisisadapterortc") + " " + i + " " + r + " IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n"
                }, t.getDirection = function(e, n) {
                    const s = t.splitLines(e);
                    for (let e = 0; e < s.length; e++) switch (s[e]) {
                        case "a=sendrecv":
                        case "a=sendonly":
                        case "a=recvonly":
                        case "a=inactive":
                            return s[e].substring(2)
                    }
                    return n ? t.getDirection(n) : "sendrecv"
                }, t.getKind = function(e) {
                    return t.splitLines(e)[0].split(" ")[0].substring(2)
                }, t.isRejected = function(e) {
                    return "0" === e.split(" ", 2)[1]
                }, t.parseMLine = function(e) {
                    const n = t.splitLines(e)[0].substring(2).split(" ");
                    return {
                        kind: n[0],
                        port: parseInt(n[1], 10),
                        protocol: n[2],
                        fmt: n.slice(3).join(" ")
                    }
                }, t.parseOLine = function(e) {
                    const n = t.matchPrefix(e, "o=")[0].substring(2).split(" ");
                    return {
                        username: n[0],
                        sessionId: n[1],
                        sessionVersion: parseInt(n[2], 10),
                        netType: n[3],
                        addressType: n[4],
                        address: n[5]
                    }
                }, t.isValidSDP = function(e) {
                    if ("string" != typeof e || 0 === e.length) return !1;
                    const n = t.splitLines(e);
                    for (let e = 0; e < n.length; e++)
                        if (n[e].length < 2 || "=" !== n[e].charAt(1)) return !1;
                    return !0
                }, e.exports = t
            },
            613: (e, t, n) => {
                n.d(t, {
                    c: () => i
                });
                var s = n(107);
                class i extends s.E {
                    constructor(e, t, n, s, i, r = () => {}) {
                        super(e, t, n, s, r), i && this.hasURLParam(this.id) ? this.text = this.getURLParam(this.id) : this.text = s, this.useUrlParams = i
                    }
                    getValueAsString() {
                        return this.text
                    }
                    get text() {
                        return this.value
                    }
                    set text(e) {
                        this.value = e
                    }
                }
            },
            656: (e, t, n) => {
                n.d(t, {
                    Bg: () => S,
                    CE: () => y,
                    Cc: () => O,
                    EG: () => N,
                    EQ: () => v,
                    FJ: () => x,
                    Fh: () => A,
                    Gi: () => D,
                    HH: () => W,
                    KB: () => j,
                    Kr: () => o,
                    L0: () => F,
                    L7: () => _,
                    Lz: () => M,
                    Nu: () => g,
                    PC: () => d,
                    Qy: () => b,
                    R5: () => Q,
                    RW: () => R,
                    S_: () => i,
                    Si: () => U,
                    Ys: () => u,
                    _h: () => V,
                    d2: () => H,
                    d4: () => m,
                    d_: () => P,
                    ev: () => B,
                    ie: () => L,
                    iu: () => w,
                    jG: () => I,
                    jr: () => r,
                    mC: () => s,
                    nV: () => h,
                    oK: () => E,
                    qM: () => z,
                    tv: () => p,
                    vL: () => T,
                    vx: () => k,
                    x1: () => a,
                    xV: () => l,
                    y6: () => C,
                    ys: () => f,
                    zx: () => c
                });
                class s extends Event {
                    constructor(e) {
                        super("afkWarningActivate"), this.data = e
                    }
                }
                class i extends Event {
                    constructor(e) {
                        super("afkWarningUpdate"), this.data = e
                    }
                }
                class r extends Event {
                    constructor() {
                        super("afkWarningDeactivate")
                    }
                }
                class o extends Event {
                    constructor() {
                        super("afkTimedOut")
                    }
                }
                class a extends Event {
                    constructor(e) {
                        super("videoEncoderAvgQP"), this.data = e
                    }
                }
                class l extends Event {
                    constructor() {
                        super("webRtcSdp")
                    }
                }
                class c extends Event {
                    constructor(e) {
                        super("webRtcSdpAnswer"), this.data = e
                    }
                }
                class d extends Event {
                    constructor(e) {
                        super("webRtcSdpOffer"), this.data = e
                    }
                }
                class h extends Event {
                    constructor() {
                        super("webRtcAutoConnect")
                    }
                }
                class u extends Event {
                    constructor() {
                        super("webRtcConnecting")
                    }
                }
                class m extends Event {
                    constructor() {
                        super("webRtcConnected")
                    }
                }
                class p extends Event {
                    constructor() {
                        super("webRtcFailed")
                    }
                }
                class g extends Event {
                    constructor(e) {
                        super("webRtcDisconnected"), this.data = e
                    }
                }
                class f extends Event {
                    constructor(e) {
                        super("dataChannelOpen"), this.data = e
                    }
                }
                class y extends Event {
                    constructor(e) {
                        super("dataChannelClose"), this.data = e
                    }
                }
                class v extends Event {
                    constructor(e) {
                        super("dataChannelError"), this.data = e
                    }
                }
                class b extends Event {
                    constructor() {
                        super("videoInitialized")
                    }
                }
                class S extends Event {
                    constructor() {
                        super("streamLoading")
                    }
                }
                class C extends Event {
                    constructor() {
                        super("streamConnect")
                    }
                }
                class w extends Event {
                    constructor() {
                        super("streamDisconnect")
                    }
                }
                class E extends Event {
                    constructor() {
                        super("streamReconnect")
                    }
                }
                class T extends Event {
                    constructor(e) {
                        super("playStreamError"), this.data = e
                    }
                }
                class M extends Event {
                    constructor() {
                        super("playStream")
                    }
                }
                class x extends Event {
                    constructor(e) {
                        super("playStreamRejected"), this.data = e
                    }
                }
                class k extends Event {
                    constructor(e) {
                        super("loadFreezeFrame"), this.data = e
                    }
                }
                class R extends Event {
                    constructor() {
                        super("hideFreezeFrame")
                    }
                }
                class P extends Event {
                    constructor(e) {
                        super("statsReceived"), this.data = e
                    }
                }
                class I extends Event {
                    constructor(e) {
                        super("streamerListMessage"), this.data = e
                    }
                }
                class L extends Event {
                    constructor(e) {
                        super("StreamerIDChangedMessage"), this.data = e
                    }
                }
                class O extends Event {
                    constructor(e) {
                        super("latencyTestResult"), this.data = e
                    }
                }
                class F extends Event {
                    constructor(e) {
                        super("latencyCalculated"), this.data = e
                    }
                }
                class D extends Event {
                    constructor(e) {
                        super("showOnScreenKeyboard"), this.data = e
                    }
                }
                class A extends Event {
                    constructor(e) {
                        super("dataChannelLatencyTestResponse"), this.data = e
                    }
                }
                class _ extends Event {
                    constructor(e) {
                        super("dataChannelLatencyTestResult"), this.data = e
                    }
                }
                class V extends Event {
                    constructor(e) {
                        super("subscribeFailed"), this.data = e
                    }
                }
                class N extends Event {
                    constructor(e) {
                        super("initialSettings"), this.data = e
                    }
                }
                class U extends Event {
                    constructor(e) {
                        super("settingsChanged"), this.data = e
                    }
                }
                class B extends Event {
                    constructor() {
                        super("xrSessionStarted")
                    }
                }
                class W extends Event {
                    constructor() {
                        super("xrSessionEnded")
                    }
                }
                class z extends Event {
                    constructor(e) {
                        super("xrFrame"), this.data = e
                    }
                }
                class H extends Event {
                    constructor(e) {
                        super("playerCount"), this.data = e
                    }
                }
                class j extends Event {
                    constructor() {
                        super("webRtcTCPRelayDetected")
                    }
                }
                class Q extends EventTarget {
                    dispatchEvent(e) {
                        return super.dispatchEvent(e)
                    }
                    addEventListener(e, t) {
                        super.addEventListener(e, t)
                    }
                    removeEventListener(e, t) {
                        super.removeEventListener(e, t)
                    }
                }
            },
            671: (e, t, n) => {
                n.d(t, {
                    G: () => r
                });
                var s = n(879),
                    i = n(107);
                class r extends i.E {
                    constructor(e, t, n, s, i, r, o = function(e) {
                        return e
                    }, a = () => {}) {
                        super(e, t, n, s, a), this._urlParamResolver = o;
                        const l = this.hasURLParam(this.id) ? this._urlParamResolver(this.getURLParam(this.id)) : s;
                        this.options = null != i ? i : [l], this.selected = l, this.useUrlParams = r
                    }
                    getValueAsString() {
                        return this.selected
                    }
                    addOnChangedListener(e) {
                        this.onChange = e
                    }
                    get options() {
                        return this._options
                    }
                    set options(e) {
                        this._options = e, this.onChangeEmit(this.selected)
                    }
                    get selected() {
                        return this.value
                    }
                    set selected(e) {
                        void 0 !== e && (this.options.includes(e) ? this.value = e : s.Vy.Error(`Could not set "${e}" as the selected option for ${this.id} because it wasn't one of the options.`))
                    }
                    set urlParamResolver(e) {
                        this._urlParamResolver = e
                    }
                }
            },
            683: (e, t, n) => {
                n.d(t, {
                    U: () => i
                });
                var s = n(107);
                class i extends s.E {
                    constructor(e, t, n, s, i, r, o, a = () => {}) {
                        if (super(e, t, n, r, a), this._min = s, this._max = i, o && this.hasURLParam(this.id)) {
                            const e = Number.parseFloat(this.getURLParam(this.id));
                            this.number = Number.isNaN(e) ? r : e
                        } else this.number = r;
                        this.useUrlParams = o
                    }
                    getValueAsString() {
                        return this.number.toString()
                    }
                    set number(e) {
                        this.value = this.clamp(e)
                    }
                    get number() {
                        return this.value
                    }
                    clamp(e) {
                        return null == this._min && null == this._max ? e : null == this._min ? Math.min(this._max, e) : null == this._max ? Math.max(this._min, e) : Math.max(Math.min(this._max, e), this._min)
                    }
                    get min() {
                        return this._min
                    }
                    get max() {
                        return this._max
                    }
                    addOnChangedListener(e) {
                        this.onChange = e
                    }
                }
            },
            709: (e, t, n) => {
                n.r(t), n.d(t, {
                    AFKOverlay: () => m,
                    ActionOverlay: () => o,
                    Application: () => K,
                    ConfigUI: () => j,
                    ConnectOverlay: () => a,
                    DisconnectOverlay: () => l,
                    ErrorOverlay: () => u,
                    InfoOverlay: () => h,
                    OverlayBase: () => r,
                    PixelStreamingApplicationStyle: () => Rt,
                    PlayOverlay: () => c,
                    SettingUIBase: () => U,
                    SettingUIFlag: () => B,
                    SettingUINumber: () => W,
                    SettingUIOption: () => H,
                    SettingUIText: () => z,
                    TextOverlay: () => d,
                    UIElementCreationMode: () => S
                });
                var s = n(442),
                    i = n(879);
                class r {
                    constructor(e, t, n) {
                        this.rootDiv = e, this.rootElement = t, this.textElement = n, this.rootElement.appendChild(this.textElement), this.hide(), this.rootDiv.appendChild(this.rootElement)
                    }
                    show() {
                        this.rootElement.classList.remove("hiddenState")
                    }
                    hide() {
                        this.rootElement.classList.add("hiddenState")
                    }
                }
                class o extends r {
                    constructor(e, t, n) {
                        super(e, t, n), this.onActionCallback = () => {
                            i.Vy.Info("Did you forget to set the onAction callback in your overlay?")
                        }
                    }
                    update(e) {
                        null == e && null == e || (this.textElement.innerHTML = e)
                    }
                    onAction(e) {
                        this.onActionCallback = e
                    }
                    activate() {
                        this.onActionCallback()
                    }
                }
                class a extends o {
                    static createRootElement() {
                        const e = document.createElement("div");
                        return e.id = "connectOverlay", e.className = "clickableState", e
                    }
                    static createContentElement() {
                        const e = document.createElement("div");
                        return e.id = "connectButton", e.innerHTML = "Click to start", e
                    }
                    constructor(e) {
                        super(e, a.createRootElement(), a.createContentElement()), this.rootElement.addEventListener("click", (() => {
                            this.activate()
                        }))
                    }
                }
                class l extends o {
                    static createRootElement() {
                        const e = document.createElement("div");
                        return e.id = "disconnectOverlay", e.className = "clickableState", e
                    }
                    static createContentElement() {
                        const e = document.createElement("div");
                        return e.id = "disconnectButton", e.innerHTML = "Click To Restart", e
                    }
                    constructor(e) {
                        super(e, l.createRootElement(), l.createContentElement()), this.rootElement.addEventListener("click", (() => {
                            this.activate()
                        }))
                    }
                }
                class c extends o {
                    static createRootElement() {
                        const e = document.createElement("div");
                        return e.id = "playOverlay", e.className = "clickableState", e
                    }
                    static createContentElement() {
                        const e = document.createElement("img");
                        return e.id = "playButton", e.src = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAPEAAAD5CAYAAAD2mNNkAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAAZdEVYdFNvZnR3YXJlAHBhaW50Lm5ldCA0LjAuMjHxIGmVAAASgklEQVR4Xu2dC7BdVX2HqUCCIRASCPjAFIQREBRBBSRYbFOt8lIrFUWRFqXWsT5wbItUqFWs0KqIMPKoYEWpRS06KDjS1BeVFkVQbCw+wCfiAwGhCKWP9PuZtU24uTe59zz22Y/vm/nGkXtz7jlrr9+sdfZea/03Wb169QtxGW62iYi0D8L7NbwYj8EdcdPyIxFpA4T2P/F/8Ua8CI/GhPnXyq+ISJMhrAlxxX9hRuYL8Sh8SPk1EWkqBHXdEFfcg6vw3fhs3Kb8uog0DQI6XYgr8rOvYsJ8OM4v/0xEmkIJ6ob4P8zIfANegCvQMIs0BQK5sRBXJMy/wIzM5+ByXFBeRkQmBUGcbYjX5S5MmM/AA3CL8nIiUjcEcJAQV9yBX8a/wSeiz5hF6obgDRPikGfMCfOX8DTcu7y0iNQBoRs2xBX/g3diwvwm3Kn8CREZJ4RtVCGuqMKcu9kn4xJ09ZfIuCBgow5xyJ3sTLNzAywrwF6J26NhFhk1BGscIV6XhPluvA6Pxx3KnxaRUUCoxh3iioQ5z5n/BY/FJeUtiMgwEKa6QlyRMN+Hn8Hn4ZblrYjIIBCiukMc8p25Ws6ZMD+zvB0RmSsEaBIhnkrew5V4EHrCiMhcKAFqCv+Nl+J+uBC9my2yMQhKk0Jcke/M78Gsy06YH1TerohMhYA0McQVP8Nz8UDcCl2bLTIVgtHkEFd8D8/E/XFrdGQWqSAQbQhxyKOpm/B03Ac9MkgkEIa2hLgiN78S5lPx0bgIvQEm/YUAtC3EFQnzzfgnuDc6zZZ+Qsdva4jX5Sv4atwXHZmlX9DhuxDikC2Qn8dXYUbmReUjinQbOntXQlyRTRafwldgwrxV+agi3YRO3rUQV/wcV+LL8DHoyZzSTejcXQ1xRc7/uhyzl3kv3Lx8dJFuQKfueohDnjFnZP4o/j7m0ZQH4Es3oDP3IcQV2f6YMF+COZjgUeiZ2dJu6MR9CvG63ILvx4zMCfO80iQi7YLO29cQV3wb34spsr4rumBE2gWdtu8hDln99S1MXeYX4M6leUSaDx3WEK8lRdYT5lR/zPlfnswpzYeOaojXJ4cSfB3Pw+fgtug0W5oJndMQT0/uZGeaXZVyfTZuV5pNpDnQMQ3xxsk0O9Ufz8ZDcdvSfCKThw5piGdP2ioF496JT0c3WcjkKR1T5kYWjCTM78DfQheMyOSgAxriwch35lR/vAbPwOXozS+pHzqeIR6Oal12wvx2fBy6yULqgw5niEdDwpyR+VpMkfXsmHIpp4wfOpohHj234RfwFNwDnWbL+KCDGeLxkJH5p3g1vg53K00uMlroXIZ4vGTBSMJ8FeZkzmWl6UVGA53KENfD/ZiyNCmynvO/FpdLIDIcdCZDXC8ZmfOd+d/wJejZXzIcdCJDXD95xpwjdnP+V74zH4Wu/pLBoPMY4smSMN+FKbJ+BBpmmRt0GkPcDBLmu/FjeAi6lFNmB53FEDeHTLPzaCoj80dwBfqMWTYMncQQN5esAPsw7lcul8j60EEMcfPJDbD3YU7l3KxcOpE10CkMcTvIVDvfmc/E3XELtPqjGOKWkhVgp+GemDD7vbnP0AEMcXtJkfU34GNxAToy9xEuvCFuP6vwJMyOqYXl0kpf4KIb4m5QncyZTRapZGGY+wIX2xB3i3vxOswmi13QaXbX4QIb4m6SY3a/iMdh7mYb5q7ChTXE3aXaaLESq7rMW5ZLL12Bi2qI+8E9eDkmzLuhYe4KXExD3B8yMt+Ol+KL0CLrXYCLaIj7R8J8K16CR6PLOdsMF88Q95fsmPoRXozPxdzNdvVX2+CiGWLJza+EOXWZj8Sd0APw2wIXyxBLqPYy34LnY8K8DA1z0+EiGWKZSgJ9I74LU2R9R3Sa3VS4OIZYZqJaynkWpsj6w0u3kSbBhTHEsjHuwxswpVwPw6Wl+0gT4IIYYpkNmWKnr1yPqf54KG5VupFMknJhRGZLwpzVX6n++DZ8GrpjapJwAQyxDELCnB1TqWTx1/gUdGSeBDS8IZZBSZBjzv76PP4VHoSGuU5ocEMsoyBhTsG4VH98Ix6A80s3k3FCQxtiGSVZMPIT/CwmzPuhz5jHCQ1siGUcZClnwvxpPAX3LF1ORg2Na4hlXGSKnQUjCfNn8PX4CNy0dD8ZBTSoIZZxkzBXI/Pn8ATMumzDPApoSEMsdZEw5zvzDzHT7JdjwuzZX8NAAxpimQSZZifMn8Tj8aGlS8pcofEMsUyKjMw5lTOnjHwcc2TQktI1ZbbQaIZYJk3CnE0WGZmvwOeh+5hnC41liKUpVCNzwvwJPBy9+bUxaCRDLE0jYb4fU/0x0+yD8cGly8pUaBxDLE0kQa7CfCfmML8D0SN2p0KjGGJpOglztWgkh/k9CT1it4LGMMTSFhLmLBrJ3exzcJ/SjfsNDWGIpY0k0D/AM/GRpTv3ExrAEEubqVaAnY5LsX93s/nQhli6QLUF8nWYI3bnYT+Wc/JBDbF0heqO9jfwlfhInI/dDjMf0BBLF0mYr8NsskiNqS2wm2Hmgxli6TJ5zpwjg/4Qd8buLRrhQxli6QM5ZjdHBh2H+c7cnUUjfBhDLH0hU+y7cCU+H7OXeV6JQnvhQxhi6RsJc0bmy/BZ+MsbYCUS7YM3b4ilryTM2QL5QUzBuHxnbt80mzdtiEVWr74NL8KUck2R9faMzLxZQyyyhozMWcp5If4uJszNP5yAN2mIRR5IVn/djOfhEdjsw/x4c4ZYZHryjPkmPBsPwYeV2DQL3pghFpmZTLFzZFDCnLrMz8DtsTkbLXgzhlhk4yTM2cu8CrNjKiNzwjz5OlO8CUMsMjcS5qzLfgumyPr2JU6TgTdgiEUGoyqynrrMv42TOTObP2yIRQYn0+ws5bwaU8r1N3HrEq964A8aYpHhSZjvwBSMS5gPwnrWZfOHDLHI6Mgz5hyxm4Jxf4kH4HjDzB8wxCKjJ2HONPuf8c9xHxzPXmZe2BCLjIdMsWMqWfwTnoiPwdGOzLygIRYZPwlzVWPqtbgXjmbBCC9kiEXqI8+Ys8nicnwN7laiODi8iCEWqZeMylmXnTCnYFxO5tyxRHLu8I8NschkSJizLvv7mJH5pbgY57Zjin9giEUmSzUyfw9TZP1Y3LZEdOPwy4ZYpBkkzKn++B38KB6F25Wozgy/ZIhFmkXCnLO/vosfwpwysqhEdn34oSEWaSYJ8y8w0+wP4GG4/oIR/qMhFmk2VZgzzU6Ys2Nq7T5m/o8hFmkHCXO2PybMF+O++CBDLNIuEuSsy8535lvxZEMs0j6qWszZJbXUEIu0i1vwrZhqFZv5nVikPWTqfA5mF9QDD+fjPxhikeaR777xdrwAn1Aiuz780BCLNIvsdMqBAqkNtRw3XBeKXzDEIpMno27Cezdeik/GBSWmG4ZfNMQikyPhzXrpVGXM6R8rcG7lVfkHhlikfhLe7FzKo6KV+Hu45m7zXOEfGmKReske4oT3k3gMblniOBi8gCEWqYeMvD/GK/F43KHEcDh4IUMsMl5yw+pHmLOoX4aDH8UzHbygIRYZD/nem5H3KjwBd8LRV1HkRQ2xyGjJ3eacNZ1iayfhr+P46hnz4oZYZDRk2pzwph7TX+CuOP76xfwRQywyHNlVVIX3VHx8iVc98AcNscjgZJFGypq+GffHwZ71DgN/1BCLzJ2f47/iWzBlTId71jsM/HFDLDI7crf5HrwG34YHY70FxaeDN2GIRTZMwpvjcK7Fd+BTcfLhreDNGGKRmcnIez2+Ew/FhTi3MivjhjdkiEXWJ0fEfhXPwmfi4hKZ5sGbM8Qia8n65lX4LkzlhYeVqDQX3qQhFlnzrPc/8FzMtsBl2Kxp80zwRg2x9J0cxn4epoBZlkjW/6x3GHjDhlj6SJZI5gTJ9+DzMeHdvMSiXfDGDbH0iWpbYMqgJLy7YLtG3qnwAQyx9IVsC7wEX4C74/h2FtUJH8QQS9fJUTg5QfI43APnle7fDfhAhli6So5//Ri+GBPeya1vHid8MEMsXSMH0X0CX4J74cLS3bsJH9AQS1fITavs6f1VeLEdz3qHgQ9piKXtZHNC1jfnELpfTpux++Gt4MMaYmkrmTZ/GV+LCW+3p80zwQc3xNI2skTyBswhdHtic7YFTgIawBBLm7gRT8HH4dbYn2nzTNAIhljaQCrkvwkT3tywGv8pkm2BxjDE0lRyokbOsjoDUyE/N6wM71RoFEMsTSPhvRPfjY/GBei0eSZoHEMsTeJ2/ADug+3cVVQ3NJQhliaQkfcf8SnoqDsXaDBDLJMij4ruxcvwaejIOwg0nCGWusnyyIT3CjwM+7lIY1TQgIZY6iA3qzLyZmdRSn0eic09QbJN0JCGWMZJwpuR9w78Er4Qu7klcFLQoIZYxkXq9OZuc2oWZXNCv5dHjgsa1hDLqKnCm2qB2Zzw0NLdZBzQwIZYRkWmzT/DhPdE3KV0MxknNLQhlmHJ996ENwXHsjkhq6xcHlkXNLYhlkFJeHPDKhvyszkh4W338a9thEY3xDJX8qgoGxMS3tTpfSzOL11K6obGN8QyWxLeLI/MtDmlPvdHp82ThotgiGU2ZOStwrsCXSLZFLgYhlg2xF2Yc6zOxqejCzWaBhfFEMt0pMj2VzB1eg/BJaXLSNPg4hhiqcjd5izUSIX8lPp8Fi4tXUWaChfJEEtIhfwU2b4QU2R7O3RfbxvgQhnifpOD17+JCW9KfS5F7zi3CS6YIe4nOXj9W/h3eAw+vHQJaRtcPEPcL/Ks92a8CI/FXdFpc5vhAhri/vB9/Hv8A3wUukSyC3AhDXH3+Sn+Ax6PqZDvEskuwQU1xN2kOgonJ0im1Gc2J2xRLrt0CS6sIe4W1c6ij2NG3lROmFcut3QRLrAh7g4J75X4R7g3Gt4+wIU2xO0n0+ZP4aswBcdc39wnuOCGuL3kWe/n8DW4Ly4ql1X6BBfeELeTL+AJ+ATcBn3W21e4+Ia4PeSO89fwT/GJuAhdItl36ASGuPlkZ9G38fWYo3Ay8hpeWQOdwRA3lxwBexO+GVPq07Insj50DEPcTLK++e2Yc6wWo995ZXroHIa4WdyKOQpnOWbavGm5VCLTQycxxM0gp0iej0/G3LAyvDI76CyGeHJUx+G8Hw9Ewytzh05jiCdDDqK7HA/Aheh3XhkMOo8hrpe096fxd9D9vDI8pVPJ+LkXP4vPQafMMjroUIZ4fOQ7b9Y3X4U5x8oi2zJ66FiGePRkeWROkfwiHoee3Szjgw5miEdDRt14D+bw9ZfjDqWZRcYHHc0QD091FE6OgP0z9OB1qQ86myEenKxtTngz8r4BHXmlfuh4hnjuJLwp9Zlqgafh7qU5ReqHDmiIZ0+mzVkeeQO+FR9fmlFkctARDfHsSJ3ef8dqZ5GH0EkzoDMa4pnJ3ea0T07TOAezvnlBaTqRZlA6qTyQhDdrm1fhBXgwGl5pJnROQ7yW6jlvwvtefAZuXppKpJmUTitrp80p9Zn1zQ8uTSTSbOisfQ9xps2pkJ/wPhe3K00j0g7otH0N8f34dXwfHo0W2ZZ2QuftY4izPDKnabwIH4Ee/yrthQ7clxBnldUP8BJ8MSa87uuV9kNH7nqIc4ZVwvshfCkuQ8Mr3YEO3dUQZ4nkD/HDmFKfe5SPLNIt6NxdDHHC+xF8BabsiSOvdBc6eJdCfBtehglvimz7rFe6Dx29CyHOQo0r8NWYOr0W2Zb+QIdva4izRDLPeldi6vSm1OfC8rFE+gMdv40hznu+GlMhfz/cEj0OR/oJnb9NIc57vQZPxCehI69ICUbTydnN1+LJmPAuKW9fRAhEk0OcZ73XYw6hOwg9v1lkKgSjqSHO5oRT8TdwKbq+WWQ6CEeTQpw7zlmocTqmTm/Ob7bomMiGICRNCHGmzT/BszClPjPyuspKZDYQlkmH+Mf4t7gct0enzSJzgdBMKsQJ70X4VHTkFRkUwlN3iFM54YN4KG6LHkQnMgyEqK4Q51nvpZjwZuQ1vCKjgDDVEeIr8XBMeL3bLDJKCNW4QpyR9zo8ArdBb1iJjAPCNeoQJ7ypFngszkc3JoiME0I2qhDnWW8Kjv0xujFBpC4I3DAhzgqrHESXUp/Z0/uQ8rIiUhcEb5AQJ7z34TfwJNy5vJyI1A0BnG2IE9yYsiffwTfizuh3XpFJQghnE+J83014v4upkL8r+qhIpAkQxg2FOOHNzzNtPhf3REdekSZRQjqVTJtzguSNeD4eWH5dRJoGAZ0a4rvxm3ghrkCnzSJNhpBWIc7/plpgwpudRZ7dLNIGCOvtJbwX42G4uPxIRNoAoU2d3iNxUflPItIaNtnk/wEGBoMdpECGHAAAAABJRU5ErkJggg==", e.alt = "Start Streaming", e
                    }
                    constructor(e) {
                        super(e, c.createRootElement(), c.createContentElement()), this.rootElement.addEventListener("click", (() => {
                            this.activate()
                        }))
                    }
                }
                class d extends r {
                    constructor(e, t, n) {
                        super(e, t, n)
                    }
                    update(e) {
                        null == e && null == e || (this.textElement.innerHTML = e)
                    }
                }
                class h extends d {
                    static createRootElement() {
                        const e = document.createElement("div");
                        return e.id = "infoOverlay", e.className = "textDisplayState", e
                    }
                    static createContentElement() {
                        const e = document.createElement("div");
                        return e.id = "messageOverlayInner", e
                    }
                    constructor(e) {
                        super(e, h.createRootElement(), h.createContentElement())
                    }
                }
                class u extends d {
                    static createRootElement() {
                        const e = document.createElement("div");
                        return e.id = "errorOverlay", e.className = "textDisplayState", e
                    }
                    static createContentElement() {
                        const e = document.createElement("div");
                        return e.id = "errorOverlayInner", e
                    }
                    constructor(e) {
                        super(e, u.createRootElement(), u.createContentElement())
                    }
                }
                class m extends o {
                    static createRootElement() {
                        const e = document.createElement("div");
                        return e.id = "afkOverlay", e.className = "clickableState", e
                    }
                    static createContentElement() {
                        const e = document.createElement("div");
                        return e.id = "afkOverlayInner", e.innerHTML = '<center>No activity detected<br>Disconnecting in <span id="afkCountDownNumber"></span> seconds<br>Click to continue<br></center>', e
                    }
                    constructor(e) {
                        super(e, m.createRootElement(), m.createContentElement()), this.rootElement.addEventListener("click", (() => {
                            this.activate()
                        }))
                    }
                    updateCountdown(e) {
                        this.textElement.innerHTML = `<center>No activity detected<br>Disconnecting in <span id="afkCountDownNumber">${e}</span> seconds<br>Click to continue<br></center>`
                    }
                }
                class p {
                    get rootElement() {
                        return this._rootElement
                    }
                    set rootElement(e) {
                        e.onclick = () => this.toggleFullscreen(), this._rootElement = e
                    }
                    constructor() {
                        this.isFullscreen = !1, document.addEventListener("webkitfullscreenchange", (() => this.onFullscreenChange()), !1), document.addEventListener("mozfullscreenchange", (() => this.onFullscreenChange()), !1), document.addEventListener("fullscreenchange", (() => this.onFullscreenChange()), !1), document.addEventListener("MSFullscreenChange", (() => this.onFullscreenChange()), !1)
                    }
                    toggleFullscreen() {
                        if (document.fullscreenElement || document.webkitFullscreenElement || document.mozFullScreenElement || document.msFullscreenElement) document.exitFullscreen ? document.exitFullscreen() : document.mozCancelFullScreen ? document.mozCancelFullScreen() : document.webkitExitFullscreen ? document.webkitExitFullscreen() : document.msExitFullscreen && document.msExitFullscreen();
                        else {
                            const e = this.fullscreenElement;
                            if (!e) return;
                            e.requestFullscreen ? e.requestFullscreen() : e.mozRequestFullscreen ? e.mozRequestFullscreen() : e.webkitRequestFullscreen ? e.webkitRequestFullscreen() : e.msRequestFullscreen ? e.msRequestFullscreen() : e.webkitEnterFullscreen && e.webkitEnterFullscreen()
                        }
                        this.onFullscreenChange()
                    }
                    onFullscreenChange() {
                        this.isFullscreen = document.webkitIsFullScreen || document.mozFullScreen || document.msFullscreenElement && null !== document.msFullscreenElement || document.fullscreenElement && null !== document.fullscreenElement
                    }
                }
                class g extends p {
                    constructor(e) {
                        super(), this.rootElement = e
                    }
                }
                class f extends p {
                    constructor() {
                        super();
                        const e = document.createElement("button");
                        e.type = "button", e.classList.add("UiTool"), e.id = "fullscreen-btn", e.appendChild(this.maximizeIcon), e.appendChild(this.minimizeIcon), e.appendChild(this.tooltipText), this.rootElement = e
                    }
                    get tooltipText() {
                        return this._tooltipText || (this._tooltipText = document.createElement("span"), this._tooltipText.classList.add("tooltiptext"), this._tooltipText.innerHTML = "Fullscreen"), this._tooltipText
                    }
                    get maximizeIcon() {
                        if (!this._maximizeIcon) {
                            this._maximizeIcon = document.createElementNS("http://www.w3.org/2000/svg", "svg"), this._maximizeIcon.setAttributeNS(null, "id", "maximizeIcon"), this._maximizeIcon.setAttributeNS(null, "x", "0px"), this._maximizeIcon.setAttributeNS(null, "y", "0px"), this._maximizeIcon.setAttributeNS(null, "viewBox", "0 0 384.97 384.97");
                            const e = document.createElementNS("http://www.w3.org/2000/svg", "g");
                            e.classList.add("svgIcon"), this._maximizeIcon.appendChild(e);
                            const t = document.createElementNS("http://www.w3.org/2000/svg", "path");
                            t.setAttributeNS(null, "d", "M384.97,12.03c0-6.713-5.317-12.03-12.03-12.03H264.847c-6.833,0-11.922,5.39-11.934,12.223c0,6.821,5.101,11.838,11.934,11.838h96.062l-0.193,96.519c0,6.833,5.197,12.03,12.03,12.03c6.833-0.012,12.03-5.197,12.03-12.03l0.193-108.369c0-0.036-0.012-0.06-0.012-0.084C384.958,12.09,384.97,12.066,384.97,12.03z");
                            const n = document.createElementNS("http://www.w3.org/2000/svg", "path");
                            n.setAttributeNS(null, "d", "M120.496,0H12.403c-0.036,0-0.06,0.012-0.096,0.012C12.283,0.012,12.247,0,12.223,0C5.51,0,0.192,5.317,0.192,12.03L0,120.399c0,6.833,5.39,11.934,12.223,11.934c6.821,0,11.838-5.101,11.838-11.934l0.192-96.339h96.242c6.833,0,12.03-5.197,12.03-12.03C132.514,5.197,127.317,0,120.496,0z");
                            const s = document.createElementNS("http://www.w3.org/2000/svg", "path");
                            s.setAttributeNS(null, "d", "M120.123,360.909H24.061v-96.242c0-6.833-5.197-12.03-12.03-12.03S0,257.833,0,264.667v108.092c0,0.036,0.012,0.06,0.012,0.084c0,0.036-0.012,0.06-0.012,0.096c0,6.713,5.317,12.03,12.03,12.03h108.092c6.833,0,11.922-5.39,11.934-12.223C132.057,365.926,126.956,360.909,120.123,360.909z");
                            const i = document.createElementNS("http://www.w3.org/2000/svg", "path");
                            i.setAttributeNS(null, "d", "M372.747,252.913c-6.833,0-11.85,5.101-11.838,11.934v96.062h-96.242c-6.833,0-12.03,5.197-12.03,12.03s5.197,12.03,12.03,12.03h108.092c0.036,0,0.06-0.012,0.084-0.012c0.036-0.012,0.06,0.012,0.096,0.012c6.713,0,12.03-5.317,12.03-12.03V264.847C384.97,258.014,379.58,252.913,372.747,252.913z"), e.appendChild(t), e.appendChild(n), e.appendChild(s), e.appendChild(i)
                        }
                        return this._maximizeIcon
                    }
                    get minimizeIcon() {
                        if (!this._minimizeIcon) {
                            this._minimizeIcon = document.createElementNS("http://www.w3.org/2000/svg", "svg"), this._minimizeIcon.setAttributeNS(null, "id", "minimizeIcon"), this._minimizeIcon.setAttributeNS(null, "x", "0px"), this._minimizeIcon.setAttributeNS(null, "y", "0px"), this._minimizeIcon.setAttributeNS(null, "viewBox", "0 0 385.331 385.331");
                            const e = document.createElementNS("http://www.w3.org/2000/svg", "g");
                            e.classList.add("svgIcon"), this._minimizeIcon.appendChild(e);
                            const t = document.createElementNS("http://www.w3.org/2000/svg", "path");
                            t.setAttributeNS(null, "d", "M264.943,156.665h108.273c6.833,0,11.934-5.39,11.934-12.211c0-6.833-5.101-11.85-11.934-11.838h-96.242V36.181c0-6.833-5.197-12.03-12.03-12.03s-12.03,5.197-12.03,12.03v108.273c0,0.036,0.012,0.06,0.012,0.084c0,0.036-0.012,0.06-0.012,0.096C252.913,151.347,258.23,156.677,264.943,156.665z");
                            const n = document.createElementNS("http://www.w3.org/2000/svg", "path");
                            n.setAttributeNS(null, "d", "M120.291,24.247c-6.821,0-11.838,5.113-11.838,11.934v96.242H12.03c-6.833,0-12.03,5.197-12.03,12.03c0,6.833,5.197,12.03,12.03,12.03h108.273c0.036,0,0.06-0.012,0.084-0.012c0.036,0,0.06,0.012,0.096,0.012c6.713,0,12.03-5.317,12.03-12.03V36.181C132.514,29.36,127.124,24.259,120.291,24.247z");
                            const s = document.createElementNS("http://www.w3.org/2000/svg", "path");
                            s.setAttributeNS(null, "d", "M120.387,228.666H12.115c-6.833,0.012-11.934,5.39-11.934,12.223c0,6.833,5.101,11.85,11.934,11.838h96.242v96.423c0,6.833,5.197,12.03,12.03,12.03c6.833,0,12.03-5.197,12.03-12.03V240.877c0-0.036-0.012-0.06-0.012-0.084c0-0.036,0.012-0.06,0.012-0.096C132.418,233.983,127.1,228.666,120.387,228.666z");
                            const i = document.createElementNS("http://www.w3.org/2000/svg", "path");
                            i.setAttributeNS(null, "d", "M373.3,228.666H265.028c-0.036,0-0.06,0.012-0.084,0.012c-0.036,0-0.06-0.012-0.096-0.012c-6.713,0-12.03,5.317-12.03,12.03v108.273c0,6.833,5.39,11.922,12.223,11.934c6.821,0.012,11.838-5.101,11.838-11.922v-96.242H373.3c6.833,0,12.03-5.197,12.03-12.03S380.134,228.678,373.3,228.666z"), e.appendChild(t), e.appendChild(n), e.appendChild(s), e.appendChild(i)
                        }
                        return this._minimizeIcon
                    }
                    onFullscreenChange() {
                        super.onFullscreenChange();
                        const e = this.minimizeIcon,
                            t = this.maximizeIcon;
                        this.isFullscreen ? (e.style.display = "inline", e.style.transform = "translate(0, 0)", t.style.display = "none") : (e.style.display = "none", t.style.display = "inline", t.style.transform = "translate(0, 0)")
                    }
                }
                class y {
                    get rootElement() {
                        return this._rootElement || (this._rootElement = document.createElement("button"), this._rootElement.type = "button", this._rootElement.classList.add("UiTool"), this._rootElement.id = "settingsBtn", this._rootElement.appendChild(this.settingsIcon), this._rootElement.appendChild(this.tooltipText)), this._rootElement
                    }
                    get tooltipText() {
                        return this._tooltipText || (this._tooltipText = document.createElement("span"), this._tooltipText.classList.add("tooltiptext"), this._tooltipText.innerHTML = "Settings"), this._tooltipText
                    }
                    get settingsIcon() {
                        if (!this._settingsIcon) {
                            this._settingsIcon = document.createElementNS("http://www.w3.org/2000/svg", "svg"), this._settingsIcon.setAttributeNS(null, "id", "settingsIcon"), this._settingsIcon.setAttributeNS(null, "x", "0px"), this._settingsIcon.setAttributeNS(null, "y", "0px"), this._settingsIcon.setAttributeNS(null, "viewBox", "0 0 478.703 478.703");
                            const e = document.createElementNS("http://www.w3.org/2000/svg", "g");
                            e.classList.add("svgIcon"), this._settingsIcon.appendChild(e);
                            const t = document.createElementNS("http://www.w3.org/2000/svg", "path");
                            t.setAttributeNS(null, "d", "M454.2,189.101l-33.6-5.7c-3.5-11.3-8-22.2-13.5-32.6l19.8-27.7c8.4-11.8,7.1-27.9-3.2-38.1l-29.8-29.8\t\t\tc-5.6-5.6-13-8.7-20.9-8.7c-6.2,0-12.1,1.9-17.1,5.5l-27.8,19.8c-10.8-5.7-22.1-10.4-33.8-13.9l-5.6-33.2\t\t\tc-2.4-14.3-14.7-24.7-29.2-24.7h-42.1c-14.5,0-26.8,10.4-29.2,24.7l-5.8,34c-11.2,3.5-22.1,8.1-32.5,13.7l-27.5-19.8\t\t\tc-5-3.6-11-5.5-17.2-5.5c-7.9,0-15.4,3.1-20.9,8.7l-29.9,29.8c-10.2,10.2-11.6,26.3-3.2,38.1l20,28.1\t\t\tc-5.5,10.5-9.9,21.4-13.3,32.7l-33.2,5.6c-14.3,2.4-24.7,14.7-24.7,29.2v42.1c0,14.5,10.4,26.8,24.7,29.2l34,5.8\t\t\tc3.5,11.2,8.1,22.1,13.7,32.5l-19.7,27.4c-8.4,11.8-7.1,27.9,3.2,38.1l29.8,29.8c5.6,5.6,13,8.7,20.9,8.7c6.2,0,12.1-1.9,17.1-5.5\t\t\tl28.1-20c10.1,5.3,20.7,9.6,31.6,13l5.6,33.6c2.4,14.3,14.7,24.7,29.2,24.7h42.2c14.5,0,26.8-10.4,29.2-24.7l5.7-33.6\t\t\tc11.3-3.5,22.2-8,32.6-13.5l27.7,19.8c5,3.6,11,5.5,17.2,5.5l0,0c7.9,0,15.3-3.1,20.9-8.7l29.8-29.8c10.2-10.2,11.6-26.3,3.2-38.1\t\t\tl-19.8-27.8c5.5-10.5,10.1-21.4,13.5-32.6l33.6-5.6c14.3-2.4,24.7-14.7,24.7-29.2v-42.1\t\t\tC478.9,203.801,468.5,191.501,454.2,189.101z M451.9,260.401c0,1.3-0.9,2.4-2.2,2.6l-42,7c-5.3,0.9-9.5,4.8-10.8,9.9\t\t\tc-3.8,14.7-9.6,28.8-17.4,41.9c-2.7,4.6-2.5,10.3,0.6,14.7l24.7,34.8c0.7,1,0.6,2.5-0.3,3.4l-29.8,29.8c-0.7,0.7-1.4,0.8-1.9,0.8\t\t\tc-0.6,0-1.1-0.2-1.5-0.5l-34.7-24.7c-4.3-3.1-10.1-3.3-14.7-0.6c-13.1,7.8-27.2,13.6-41.9,17.4c-5.2,1.3-9.1,5.6-9.9,10.8l-7.1,42\t\t\tc-0.2,1.3-1.3,2.2-2.6,2.2h-42.1c-1.3,0-2.4-0.9-2.6-2.2l-7-42c-0.9-5.3-4.8-9.5-9.9-10.8c-14.3-3.7-28.1-9.4-41-16.8\t\t\tc-2.1-1.2-4.5-1.8-6.8-1.8c-2.7,0-5.5,0.8-7.8,2.5l-35,24.9c-0.5,0.3-1,0.5-1.5,0.5c-0.4,0-1.2-0.1-1.9-0.8l-29.8-29.8\t\t\tc-0.9-0.9-1-2.3-0.3-3.4l24.6-34.5c3.1-4.4,3.3-10.2,0.6-14.8c-7.8-13-13.8-27.1-17.6-41.8c-1.4-5.1-5.6-9-10.8-9.9l-42.3-7.2\t\t\tc-1.3-0.2-2.2-1.3-2.2-2.6v-42.1c0-1.3,0.9-2.4,2.2-2.6l41.7-7c5.3-0.9,9.6-4.8,10.9-10c3.7-14.7,9.4-28.9,17.1-42\t\t\tc2.7-4.6,2.4-10.3-0.7-14.6l-24.9-35c-0.7-1-0.6-2.5,0.3-3.4l29.8-29.8c0.7-0.7,1.4-0.8,1.9-0.8c0.6,0,1.1,0.2,1.5,0.5l34.5,24.6\t\t\tc4.4,3.1,10.2,3.3,14.8,0.6c13-7.8,27.1-13.8,41.8-17.6c5.1-1.4,9-5.6,9.9-10.8l7.2-42.3c0.2-1.3,1.3-2.2,2.6-2.2h42.1\t\t\tc1.3,0,2.4,0.9,2.6,2.2l7,41.7c0.9,5.3,4.8,9.6,10,10.9c15.1,3.8,29.5,9.7,42.9,17.6c4.6,2.7,10.3,2.5,14.7-0.6l34.5-24.8\t\t\tc0.5-0.3,1-0.5,1.5-0.5c0.4,0,1.2,0.1,1.9,0.8l29.8,29.8c0.9,0.9,1,2.3,0.3,3.4l-24.7,34.7c-3.1,4.3-3.3,10.1-0.6,14.7\t\t\tc7.8,13.1,13.6,27.2,17.4,41.9c1.3,5.2,5.6,9.1,10.8,9.9l42,7.1c1.3,0.2,2.2,1.3,2.2,2.6v42.1H451.9z");
                            const n = document.createElementNS("http://www.w3.org/2000/svg", "path");
                            n.setAttributeNS(null, "d", "M239.4,136.001c-57,0-103.3,46.3-103.3,103.3s46.3,103.3,103.3,103.3s103.3-46.3,103.3-103.3S296.4,136.001,239.4,136.001z M239.4,315.601c-42.1,0-76.3-34.2-76.3-76.3s34.2-76.3,76.3-76.3s76.3,34.2,76.3,76.3S281.5,315.601,239.4,315.601z"), e.appendChild(t), e.appendChild(n)
                        }
                        return this._settingsIcon
                    }
                }
                class v {
                    get rootElement() {
                        return this._rootElement || (this._rootElement = document.createElement("button"), this._rootElement.type = "button", this._rootElement.classList.add("UiTool"), this._rootElement.id = "statsBtn", this._rootElement.appendChild(this.statsIcon), this._rootElement.appendChild(this.tooltipText)), this._rootElement
                    }
                    get tooltipText() {
                        return this._tooltipText || (this._tooltipText = document.createElement("span"), this._tooltipText.classList.add("tooltiptext"), this._tooltipText.innerHTML = "Information"), this._tooltipText
                    }
                    get statsIcon() {
                        if (!this._statsIcon) {
                            this._statsIcon = document.createElementNS("http://www.w3.org/2000/svg", "svg"), this._statsIcon.setAttributeNS(null, "id", "statsIcon"), this._statsIcon.setAttributeNS(null, "x", "0px"), this._statsIcon.setAttributeNS(null, "y", "0px"), this._statsIcon.setAttributeNS(null, "viewBox", "0 0 330 330");
                            const e = document.createElementNS("http://www.w3.org/2000/svg", "g");
                            e.classList.add("svgIcon"), this._statsIcon.appendChild(e);
                            const t = document.createElementNS("http://www.w3.org/2000/svg", "path");
                            t.setAttributeNS(null, "d", "M165,0.008C74.019,0.008,0,74.024,0,164.999c0,90.977,74.019,164.992,165,164.992s165-74.015,165-164.992C330,74.024,255.981,0.008,165,0.008z M165,299.992c-74.439,0-135-60.557-135-134.992S90.561,30.008,165,30.008s135,60.557,135,134.991C300,239.436,239.439,299.992,165,299.992z");
                            const n = document.createElementNS("http://www.w3.org/2000/svg", "path");
                            n.setAttributeNS(null, "d", "M165,130.008c-8.284,0-15,6.716-15,15v99.983c0,8.284,6.716,15,15,15s15-6.716,15-15v-99.983C180,136.725,173.284,130.008,165,130.008z");
                            const s = document.createElementNS("http://www.w3.org/2000/svg", "path");
                            s.setAttributeNS(null, "d", "M165,70.011c-3.95,0-7.811,1.6-10.61,4.39c-2.79,2.79-4.39,6.66-4.39,10.61s1.6,7.81,4.39,10.61c2.79,2.79,6.66,4.39,10.61,4.39s7.81-1.6,10.609-4.39c2.79-2.8,4.391-6.66,4.391-10.61s-1.601-7.82-4.391-10.61C172.81,71.61,168.95,70.011,165,70.011z"), e.appendChild(t), e.appendChild(n), e.appendChild(s)
                        }
                        return this._statsIcon
                    }
                }
                class b {
                    get rootElement() {
                        return this._rootElement || (this._rootElement = document.createElement("button"), this._rootElement.type = "button", this._rootElement.classList.add("UiTool"), this._rootElement.id = "xrBtn", this._rootElement.appendChild(this.xrIcon), this._rootElement.appendChild(this.tooltipText)), this._rootElement
                    }
                    get tooltipText() {
                        return this._tooltipText || (this._tooltipText = document.createElement("span"), this._tooltipText.classList.add("tooltiptext"), this._tooltipText.innerHTML = "XR"), this._tooltipText
                    }
                    get xrIcon() {
                        if (!this._xrIcon) {
                            this._xrIcon = document.createElementNS("http://www.w3.org/2000/svg", "svg"), this._xrIcon.setAttributeNS(null, "id", "xrIcon"), this._xrIcon.setAttributeNS(null, "x", "0px"), this._xrIcon.setAttributeNS(null, "y", "0px"), this._xrIcon.setAttributeNS(null, "viewBox", "0 0 100 100");
                            const e = document.createElementNS("http://www.w3.org/2000/svg", "g");
                            e.classList.add("svgIcon"), this._xrIcon.appendChild(e);
                            const t = document.createElementNS("http://www.w3.org/2000/svg", "path");
                            t.setAttributeNS(null, "d", "M29 41c-5 0-9 4-9 9s4 9 9 9 9-4 9-9-4-9-9-9zm0 14c-2.8 0-5-2.2-5-5s2.2-5 5-5 5 2.2 5 5-2.2 5-5 5zm42-14c-5 0-9 4-9 9s4 9 9 9 9-4 9-9-4-9-9-9zm0 14c-2.8 0-5-2.2-5-5s2.2-5 5-5 5 2.2 5 5-2.2 5-5 5zm12-31H17c-6.6 0-12 5.4-12 12v28c0 6.6 5.4 12 12 12h14.5c3.5 0 6.8-1.5 9-4.1l3.5-4c1.5-1.7 3.7-2.7 6-2.7s4.5 1 6 2.7l3.5 4c2.3 2.6 5.6 4.1 9 4.1H83c6.6 0 12-5.4 12-12V36c0-6.6-5.4-12-12-12zm8 40c0 4.4-3.6 8-8 8H68.5c-2.3 0-4.5-1-6-2.7l-3.5-4c-2.3-2.6-5.6-4.1-9-4.1-3.5 0-6.8 1.5-9 4.1l-3.5 4C36 71 33.8 72 31.5 72H17c-4.4 0-8-3.6-8-8V36c0-4.4 3.6-8 8-8h66c4.4 0 8 3.6 8 8v28z"), e.appendChild(t)
                        }
                        return this._xrIcon
                    }
                }
                var S, C = n(359);
                class w {}
                w.LightMode = "LightMode";
                class E {}
                E.PixelStreaming = "Pixel Streaming", E.UI = "UI", E.Input = "Input", E.Encoder = "Encoder", E.WebRTC = "WebRTC", E.Commands = "Commands";
                class T {}

                function M(e) {
                    return !e || !!e && e.isEnabled
                }

                function x(e, t) {
                    return !e || !!e && (!Object.prototype.hasOwnProperty.call(e.sectionVisibility, t) || Object.prototype.hasOwnProperty.call(e.sectionVisibility, t) && e.sectionVisibility[t])
                }

                function k(e, t) {
                    return !e || !!e && (!Object.prototype.hasOwnProperty.call(e.settingVisibility, t) || Object.prototype.hasOwnProperty.call(e.settingVisibility, t) && e.settingVisibility[t])
                }

                function R(e) {
                    return null == e || e.creationMode === S.CreateDefaultElement
                }
                T.SessionStats = "Session Stats", T.LatencyStats = "Latency Stats", T.LatencyTest = "Latency Test", T.DataChannelLatencyTest = "Data Channel Latency Test",
                    function(e) {
                        e[e.CreateDefaultElement = 0] = "CreateDefaultElement", e[e.UseCustomElement = 1] = "UseCustomElement", e[e.Disable = 2] = "Disable"
                    }(S || (S = {}));
                class P {
                    constructor(e) {
                        this.config = e, e && !R(e.statsButtonType) || (this.statsIcon = new v), e && !R(e.settingsButtonType) || (this.settingsIcon = new y), e && !R(e.fullscreenButtonType) || (this.fullscreenIcon = new f), e && !R(e.xrIconType) || (this.xrIcon = new b)
                    }
                    get rootElement() {
                        return this._rootElement || (this._rootElement = document.createElement("div"), this._rootElement.id = "controls", this.fullscreenIcon && this._rootElement.appendChild(this.fullscreenIcon.rootElement), this.settingsIcon && this._rootElement.appendChild(this.settingsIcon.rootElement), this.statsIcon && this._rootElement.appendChild(this.statsIcon.rootElement), this.xrIcon && C.R.isSessionSupported("immersive-vr").then((e => {
                            e && this._rootElement.appendChild(this.xrIcon.rootElement)
                        })), document.addEventListener("fullscreenchange", this.handleFullscreenChange.bind(this))), this._rootElement
                    }
                    handleFullscreenChange() {
                        var e;
                        !!document.fullscreenElement && (null === (e = this.config) || void 0 === e ? void 0 : e.hideControlsInFullscreen) ? this._rootElement.style.visibility = "hidden" : this._rootElement.style.visibility = "visible"
                    }
                }
                class I {
                    constructor(e, t) {
                        this._label = e, this._buttonText = t
                    }
                    addOnClickListener(e) {
                        this.button.addEventListener("click", e)
                    }
                    get button() {
                        return this._button || (this._button = document.createElement("input"), this._button.type = "button", this._button.value = this._buttonText, this._button.classList.add("overlay-button"), this._button.classList.add("btn-flat")), this._button
                    }
                    get rootElement() {
                        if (!this._rootElement) {
                            this._rootElement = document.createElement("div"), this._rootElement.classList.add("setting");
                            const e = document.createElement("div");
                            e.innerText = this._label, this._rootElement.appendChild(e);
                            const t = document.createElement("label");
                            t.classList.add("btn-overlay"), this._rootElement.appendChild(t), t.appendChild(this.button)
                        }
                        return this._rootElement
                    }
                }
                class L {
                    constructor() {
                        this._rootElement = null
                    }
                    get rootElement() {
                        if (!this._rootElement) {
                            this._rootElement = document.createElement("div"), this._rootElement.id = "settings-panel", this._rootElement.classList.add("panel-wrap");
                            const e = document.createElement("div");
                            e.classList.add("panel"), this._rootElement.appendChild(e);
                            const t = document.createElement("div");
                            t.id = "settingsHeading", t.textContent = "Settings", e.appendChild(t), e.appendChild(this.settingsCloseButton), e.appendChild(this.settingsContentElement)
                        }
                        return this._rootElement
                    }
                    get settingsContentElement() {
                        return this._settingsContentElement || (this._settingsContentElement = document.createElement("div"), this._settingsContentElement.id = "settingsContent"), this._settingsContentElement
                    }
                    get settingsCloseButton() {
                        return this._settingsCloseButton || (this._settingsCloseButton = document.createElement("div"), this._settingsCloseButton.id = "settingsClose"), this._settingsCloseButton
                    }
                    show() {
                        this.rootElement.classList.contains("panel-wrap-visible") || this.rootElement.classList.add("panel-wrap-visible")
                    }
                    toggleVisibility() {
                        this.rootElement.classList.toggle("panel-wrap-visible")
                    }
                    hide() {
                        this.rootElement.classList.contains("panel-wrap-visible") && this.rootElement.classList.remove("panel-wrap-visible")
                    }
                }
                class O {
                    get rootElement() {
                        if (!this._rootElement) {
                            this._rootElement = document.createElement("section"), this._rootElement.classList.add("settingsContainer");
                            const e = document.createElement("div");
                            e.id = "latencyTestHeader", e.classList.add("settings-text"), e.classList.add("settingsHeader"), this._rootElement.appendChild(e);
                            const t = document.createElement("div");
                            t.innerHTML = T.LatencyTest, e.appendChild(t), e.appendChild(this.latencyTestButton);
                            const n = document.createElement("div");
                            n.id = "latencyTestContainer", n.classList.add("d-none"), this._rootElement.appendChild(n), n.appendChild(this.latencyTestResultsElement)
                        }
                        return this._rootElement
                    }
                    get latencyTestResultsElement() {
                        return this._latencyTestResultsElement || (this._latencyTestResultsElement = document.createElement("div"), this._latencyTestResultsElement.id = "latencyStatsResults", this._latencyTestResultsElement.classList.add("StatsResult")), this._latencyTestResultsElement
                    }
                    get latencyTestButton() {
                        return this._latencyTestButton || (this._latencyTestButton = document.createElement("input"), this._latencyTestButton.type = "button", this._latencyTestButton.value = "Run Test", this._latencyTestButton.id = "btn-start-latency-test", this._latencyTestButton.classList.add("streamTools-button"), this._latencyTestButton.classList.add("btn-flat")), this._latencyTestButton
                    }
                    handleTestResult(e) {
                        i.Vy.Info(JSON.stringify(e));
                        let t = "";
                        void 0 !== e.networkLatency && e.networkLatency > 0 && (t += "<div>Net latency RTT (ms): " + e.networkLatency + "</div>"), void 0 !== e.EncodeMs && e.EncodeMs > 0 && (t += "<div>UE Encode (ms): " + e.EncodeMs + "</div>"), void 0 !== e.CaptureToSendMs && e.CaptureToSendMs > 0 && (t += "<div>UE Capture (ms): " + e.CaptureToSendMs + "</div>"), void 0 !== e.browserSendLatency && e.browserSendLatency > 0 && (t += "<div>Browser send latency (ms): " + e.browserSendLatency + "</div>"), void 0 !== e.frameDisplayDeltaTimeMs && void 0 !== e.browserReceiptTimeMs && (t += e.frameDisplayDeltaTimeMs && e.browserReceiptTimeMs ? "<div>Browser receive latency (ms): " + e.frameDisplayDeltaTimeMs + "</div>" : ""), void 0 !== e.latencyExcludingDecode && (t += "<div>Total latency (excluding browser) (ms): " + e.latencyExcludingDecode + "</div>"), void 0 !== e.endToEndLatency && (t += e.endToEndLatency ? "<div>Total latency (ms): " + e.endToEndLatency + "</div>" : ""), this.latencyTestResultsElement.innerHTML = t
                    }
                }
                class F {
                    static formatBytes(e, t) {
                        if (0 === e) return "0";
                        const n = t < 0 ? 0 : t,
                            s = Math.floor(Math.log(e) / Math.log(1024));
                        return parseFloat((e / Math.pow(1024, s)).toFixed(n)) + " " + ["Bytes", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"][s]
                    }
                }
                class D {
                    get rootElement() {
                        if (!this._rootElement) {
                            this._rootElement = document.createElement("section"), this._rootElement.classList.add("settingsContainer");
                            const e = document.createElement("div");
                            e.id = "dataChannelLatencyTestHeader", e.classList.add("settings-text"), e.classList.add("settingsHeader"), this._rootElement.appendChild(e);
                            const t = document.createElement("div");
                            t.innerHTML = T.DataChannelLatencyTest, e.appendChild(t), e.appendChild(this.latencyTestButton);
                            const n = document.createElement("div");
                            n.id = "dataChannelLatencyTestContainer", n.classList.add("d-none"), this._rootElement.appendChild(n), n.appendChild(this.latencyTestResultsElement)
                        }
                        return this._rootElement
                    }
                    get latencyTestResultsElement() {
                        return this._latencyTestResultsElement || (this._latencyTestResultsElement = document.createElement("div"), this._latencyTestResultsElement.id = "dataChannelLatencyStatsResults", this._latencyTestResultsElement.classList.add("StatsResult")), this._latencyTestResultsElement
                    }
                    get latencyTestButton() {
                        return this._latencyTestButton || (this._latencyTestButton = document.createElement("input"), this._latencyTestButton.type = "button", this._latencyTestButton.value = "Run Test", this._latencyTestButton.id = "btn-start-data-channel-latency-test", this._latencyTestButton.classList.add("streamTools-button"), this._latencyTestButton.classList.add("btn-flat")), this._latencyTestButton
                    }
                    handleTestResult(e) {
                        if (i.Vy.Info(JSON.stringify(e)), isNaN(e.dataChannelRtt)) return void(this.latencyTestResultsElement.innerHTML = "<div>Not supported</div>");
                        let t = "";
                        t += "<div>Data channel RTT (ms): " + e.dataChannelRtt + "</div>", e.playerToStreamerTime >= 0 && e.streamerToPlayerTime >= 0 && (t += "<div>Player to Streamer path (ms): " + e.playerToStreamerTime + "</div>", t += "<div>Streamer to Player path (ms): " + e.streamerToPlayerTime + "</div>"), this.latencyTestResultsElement.innerHTML = t;
                        const n = document.createElement("input");
                        n.type = "button", n.value = "Download", n.classList.add("streamTools-button"), n.classList.add("btn-flat"), n.onclick = () => {
                            const t = new Blob([e.exportLatencyAsCSV()], {
                                    type: "text/plain"
                                }),
                                n = document.createElement("a"),
                                s = URL.createObjectURL(t);
                            n.href = s, n.download = "data_channel_latency_test_results.csv", document.body.appendChild(n), n.click(), setTimeout((function() {
                                document.body.removeChild(n), window.URL.revokeObjectURL(s)
                            }), 0)
                        }, this.latencyTestResultsElement.appendChild(n)
                    }
                    handleTestStart() {
                        this.latencyTestResultsElement.innerHTML = "<div>Test in progress</div>"
                    }
                }
                class A {}
                class _ {
                    constructor(e) {
                        this.statsMap = new Map, this._config = e, this.latencyTest = new O, this.dataChannelLatencyTest = new D
                    }
                    get rootElement() {
                        if (!this._rootElement) {
                            this._rootElement = document.createElement("div"), this._rootElement.id = "stats-panel", this._rootElement.classList.add("panel-wrap");
                            const e = document.createElement("div");
                            e.classList.add("panel"), this._rootElement.appendChild(e);
                            const t = document.createElement("div");
                            t.id = "statsHeading", t.textContent = "Information", e.appendChild(t), e.appendChild(this.statsCloseButton), e.appendChild(this.statsContentElement)
                        }
                        return this._rootElement
                    }
                    get statsContentElement() {
                        if (!this._statsContentElement) {
                            this._statsContentElement = document.createElement("div"), this._statsContentElement.id = "statsContent";
                            const e = document.createElement("div");
                            e.id = "streamToolsStats", e.classList.add("container");
                            const t = document.createElement("div");
                            t.id = "ControlStats", t.classList.add("row");
                            const n = document.createElement("section");
                            n.id = "statistics", n.classList.add("settingsContainer");
                            const s = document.createElement("section");
                            s.id = "latencyStats", s.classList.add("settingsContainer");
                            const i = document.createElement("div");
                            i.id = "statisticsHeader", i.classList.add("settings-text"), i.classList.add("settingsHeader");
                            const r = document.createElement("div");
                            if (r.id = "latencyStatsHeader", r.classList.add("settings-text"), r.classList.add("settingsHeader"), this._statsContentElement.appendChild(e), e.appendChild(t), t.appendChild(n), t.appendChild(s), n.appendChild(i), s.appendChild(r), x(this._config, T.SessionStats)) {
                                const e = document.createElement("div");
                                e.innerHTML = T.SessionStats, i.appendChild(e)
                            }
                            if (n.appendChild(this.statisticsContainer), x(this._config, T.LatencyStats)) {
                                const e = document.createElement("div");
                                e.innerHTML = T.LatencyStats, r.appendChild(e)
                            }
                            s.appendChild(this.latencyStatsContainer), x(this._config, T.LatencyTest) && t.appendChild(this.latencyTest.rootElement), x(this._config, T.DataChannelLatencyTest) && t.appendChild(this.dataChannelLatencyTest.rootElement)
                        }
                        return this._statsContentElement
                    }
                    get statisticsContainer() {
                        return this._statisticsContainer || (this._statisticsContainer = document.createElement("div"), this._statisticsContainer.id = "statisticsContainer", this._statisticsContainer.classList.add("d-none"), this._statisticsContainer.appendChild(this.statsResult)), this._statisticsContainer
                    }
                    get latencyStatsContainer() {
                        return this._latencyStatsContainer || (this._latencyStatsContainer = document.createElement("div"), this._latencyStatsContainer.id = "latencyStatsContainer", this._latencyStatsContainer.classList.add("d-none"), this._latencyStatsContainer.appendChild(this.latencyResult)), this._latencyStatsContainer
                    }
                    get statsResult() {
                        return this._statsResult || (this._statsResult = document.createElement("div"), this._statsResult.id = "statisticsResult", this._statsResult.classList.add("StatsResult")), this._statsResult
                    }
                    get latencyResult() {
                        return this._latencyResult || (this._latencyResult = document.createElement("div"), this._latencyResult.id = "latencyResult", this._latencyResult.classList.add("StatsResult")), this._latencyResult
                    }
                    get statsCloseButton() {
                        return this._statsCloseButton || (this._statsCloseButton = document.createElement("div"), this._statsCloseButton.id = "statsClose"), this._statsCloseButton
                    }
                    onDisconnect() {
                        this.latencyTest.latencyTestButton.onclick = () => {}, this.dataChannelLatencyTest.latencyTestButton.onclick = () => {}
                    }
                    onVideoInitialized(e) {
                        this.latencyTest.latencyTestButton.onclick = () => {
                            e.requestLatencyTest()
                        }, this.dataChannelLatencyTest.latencyTestButton.onclick = () => {
                            e.requestDataChannelLatencyTest({
                                duration: 1e3,
                                rps: 10,
                                requestSize: 200,
                                responseSize: 200
                            }) && this.dataChannelLatencyTest.handleTestStart()
                        }
                    }
                    configure(e) {
                        e.DisableLatencyTest && (this.latencyTest.latencyTestButton.disabled = !0, this.latencyTest.latencyTestButton.title = "Disabled by -PixelStreamingDisableLatencyTester=true", this.dataChannelLatencyTest.latencyTestButton.disabled = !0, this.dataChannelLatencyTest.latencyTestButton.title = "Disabled by -PixelStreamingDisableLatencyTester=true", i.Vy.Info("-PixelStreamingDisableLatencyTester=true, requesting latency report from the the browser to UE is disabled."))
                    }
                    show() {
                        this.rootElement.classList.contains("panel-wrap-visible") || this.rootElement.classList.add("panel-wrap-visible")
                    }
                    toggleVisibility() {
                        this.rootElement.classList.toggle("panel-wrap-visible")
                    }
                    hide() {
                        this.rootElement.classList.contains("panel-wrap-visible") && this.rootElement.classList.remove("panel-wrap-visible")
                    }
                    handlePlayerCount(e) {
                        this.addOrUpdateSessionStat("PlayerCountStat", "Players", e.toString())
                    }
                    handleStats(e) {
                        var t, n, s, r;
                        const o = new Intl.NumberFormat(window.navigator.language, {
                                maximumFractionDigits: 0
                            }),
                            a = F.formatBytes(e.inboundVideoStats.bytesReceived, 2);
                        this.addOrUpdateSessionStat("InboundDataStat", "Received", a);
                        const l = Object.prototype.hasOwnProperty.call(e.inboundVideoStats, "packetsLost") ? o.format(e.inboundVideoStats.packetsLost) : "Chrome only";
                        this.addOrUpdateSessionStat("PacketsLostStat", "Packets Lost", l), e.inboundVideoStats.bitrate && this.addOrUpdateSessionStat("VideoBitrateStat", "Video Bitrate (kbps)", e.inboundVideoStats.bitrate.toString()), e.inboundAudioStats.bitrate && this.addOrUpdateSessionStat("AudioBitrateStat", "Audio Bitrate (kbps)", e.inboundAudioStats.bitrate.toString());
                        const c = void 0 !== e.inboundVideoStats.frameWidth && e.inboundVideoStats.frameWidth > 0 && void 0 !== e.inboundVideoStats.frameHeight && e.inboundVideoStats.frameHeight > 0 ? e.inboundVideoStats.frameWidth + "x" + e.inboundVideoStats.frameHeight : "Chrome only";
                        if (this.addOrUpdateSessionStat("VideoResStat", "Video resolution", c), void 0 !== e.inboundVideoStats.framesDecoded) {
                            const t = o.format(e.inboundVideoStats.framesDecoded);
                            this.addOrUpdateSessionStat("FramesDecodedStat", "Frames Decoded", t)
                        }
                        e.inboundVideoStats.framesPerSecond && this.addOrUpdateSessionStat("FramerateStat", "Framerate", e.inboundVideoStats.framesPerSecond.toString()), void 0 !== e.inboundVideoStats.framesDropped && this.addOrUpdateSessionStat("FramesDroppedStat", "Frames dropped", e.inboundVideoStats.framesDropped.toString()), e.inboundVideoStats.codecId && this.addOrUpdateSessionStat("VideoCodecStat", "Video codec", null !== (n = null === (t = e.codecs.get(e.inboundVideoStats.codecId)) || void 0 === t ? void 0 : t.mimeType.replace("video/", "")) && void 0 !== n ? n : ""), e.inboundAudioStats.codecId && this.addOrUpdateSessionStat("AudioCodecStat", "Audio codec", null !== (r = null === (s = e.codecs.get(e.inboundAudioStats.codecId)) || void 0 === s ? void 0 : s.mimeType.replace("audio/", "")) && void 0 !== r ? r : "");
                        const d = e.getActiveCandidatePair();
                        if (d) {
                            const t = Object.prototype.hasOwnProperty.call(d, "currentRoundTripTime") && e.isNumber(d.currentRoundTripTime) ? Math.ceil(1e3 * d.currentRoundTripTime).toString() : "Can't calculate";
                            this.addOrUpdateSessionStat("RTTStat", "Net RTT (ms)", t)
                        }
                        this.addOrUpdateSessionStat("DurationStat", "Duration", e.sessionStats.runTime), this.addOrUpdateSessionStat("ControlsInputStat", "Controls stream input", e.sessionStats.controlsStreamInput), void 0 === e.sessionStats.videoEncoderAvgQP || Number.isNaN(e.sessionStats.videoEncoderAvgQP) || this.addOrUpdateSessionStat("QPStat", "Video quantization parameter", e.sessionStats.videoEncoderAvgQP.toString()), i.Vy.Info(`--------- Stats ---------\n ${JSON.stringify(e)}\n------------------------`)
                    }
                    handleLatencyInfo(e) {
                        void 0 !== e.frameTiming && (void 0 !== e.frameTiming.encoderLatencyMs && this.addOrUpdateLatencyStat("EncodeLatency", "Encode latency (ms)", Math.ceil(e.frameTiming.encoderLatencyMs).toString()), void 0 !== e.frameTiming.packetizeLatencyMs && this.addOrUpdateLatencyStat("PacketizerLatency", "Packetizer latency (ms)", Math.ceil(e.frameTiming.packetizeLatencyMs).toString()), void 0 !== e.frameTiming.pacerLatencyMs && this.addOrUpdateLatencyStat("PacerLatency", "Pacer latency (ms)", Math.ceil(e.frameTiming.pacerLatencyMs).toString()), void 0 !== e.frameTiming.captureToSendLatencyMs && this.addOrUpdateLatencyStat("VideoTimingCaptureToSend", "Post-capture to send latency (ms)", Math.ceil(e.frameTiming.captureToSendLatencyMs).toString())), void 0 !== e.senderLatencyMs && this.addOrUpdateLatencyStat("AbsCaptureTimeToSendLatency", "Post-capture (abs-ct) to send latency (ms)", Math.ceil(e.senderLatencyMs).toString()), void 0 !== e.averageAssemblyDelayMs && this.addOrUpdateLatencyStat("AvgAssemblyDelay", "Assembly delay (ms)", Math.ceil(e.averageAssemblyDelayMs).toString()), void 0 !== e.averageDecodeLatencyMs && this.addOrUpdateLatencyStat("AvgDecodeDelay", "Decode time (ms)", Math.ceil(e.averageDecodeLatencyMs).toString()), void 0 !== e.averageJitterBufferDelayMs && this.addOrUpdateLatencyStat("AvgJitterBufferDelay", "Jitter buffer (ms)", Math.ceil(e.averageJitterBufferDelayMs).toString()), void 0 !== e.averageProcessingDelayMs && this.addOrUpdateLatencyStat("AvgProcessingDelay", "Processing delay (ms)", Math.ceil(e.averageProcessingDelayMs).toString()), void 0 !== e.averageE2ELatency && this.addOrUpdateLatencyStat("AvgE2ELatency", "Total latency (ms)", Math.ceil(e.averageE2ELatency).toString())
                    }
                    addOrUpdateSessionStat(e, t, n) {
                        this.addOrUpdateStat(T.SessionStats, e, t, n)
                    }
                    addOrUpdateLatencyStat(e, t, n) {
                        this.addOrUpdateStat(T.LatencyStats, e, t, n)
                    }
                    addOrUpdateStat(e, t, n, s) {
                        if (e === T.SessionStats && !x(this._config, T.SessionStats)) return;
                        if (e === T.LatencyStats && !x(this._config, T.LatencyStats)) return;
                        if (e !== T.SessionStats && e !== T.LatencyStats) return;
                        const i = e === T.SessionStats ? this.statsResult : this.latencyResult,
                            r = `${n}: ${s}`;
                        if (this.statsMap.has(t)) {
                            const e = this.statsMap.get(t);
                            void 0 !== e && (e.element.innerHTML = r)
                        } else {
                            const e = new A;
                            e.id = t, e.stat = s, e.title = n, e.element = document.createElement("div"), e.element.innerHTML = r, i.appendChild(e.element), this.statsMap.set(t, e)
                        }
                    }
                }
                class V {
                    constructor(e) {
                        this.videoEncoderAvgQP = -1, this.statsText = "", this.color = "", this.orangeQP = 26, this.redQP = 35, this.config = e
                    }
                    get rootElement() {
                        return this._rootElement || (this._rootElement = document.createElement("div"), this._rootElement.id = "connection", this._rootElement.classList.add("UiTool"), this._rootElement.appendChild(this.qualityStatus), this._rootElement.appendChild(this.qualityText), this.updateQpTooltip(-1)), this._rootElement
                    }
                    get qualityText() {
                        return this._qualityText || (this._qualityText = document.createElement("span"), this._qualityText.id = "qualityText", this._qualityText.classList.add("tooltiptext")), this._qualityText
                    }
                    get qualityStatus() {
                        return this._qualityStatus || (this._qualityStatus = document.createElementNS("http://www.w3.org/2000/svg", "svg"), this._qualityStatus.setAttributeNS(null, "id", "connectionStrength"), this._qualityStatus.setAttributeNS(null, "x", "0px"), this._qualityStatus.setAttributeNS(null, "y", "0px"), this._qualityStatus.setAttributeNS(null, "viewBox", "0 0 494.45 494.45"), this.qualityStatus.appendChild(this.dot), this.qualityStatus.appendChild(this.middle), this.qualityStatus.appendChild(this.outer), this.qualityStatus.appendChild(this.inner)), this._qualityStatus
                    }
                    get dot() {
                        return this._dot || (this._dot = document.createElementNS("http://www.w3.org/2000/svg", "circle"), this._dot.setAttributeNS(null, "id", "dot"), this._dot.setAttributeNS(null, "cx", "247.125"), this._dot.setAttributeNS(null, "cy", "398.925"), this._dot.setAttributeNS(null, "r", "35.3")), this._dot
                    }
                    get outer() {
                        return this._outer || (this._outer = document.createElementNS("http://www.w3.org/2000/svg", "path"), this._outer.setAttributeNS(null, "id", "outer"), this._outer.setAttributeNS(null, "d", "M467.925,204.625c-6.8,0-13.5-2.6-18.7-7.8c-111.5-111.4-292.7-111.4-404.1,0c-10.3,10.3-27.1,10.3-37.4,0s-10.3-27.1,0-37.4c64-64,149-99.2,239.5-99.2s175.5,35.2,239.5,99.2c10.3,10.3,10.3,27.1,0,37.4C481.425,202.025,474.625,204.625,467.925,204.625z")), this._outer
                    }
                    get middle() {
                        return this._middle || (this._middle = document.createElementNS("http://www.w3.org/2000/svg", "path"), this._middle.setAttributeNS(null, "id", "middle"), this._middle.setAttributeNS(null, "d", "M395.225,277.325c-6.8,0-13.5-2.6-18.7-7.8c-71.4-71.3-187.4-71.3-258.8,0c-10.3,10.3-27.1,10.3-37.4,0s-10.3-27.1,0-37.4c92-92,241.6-92,333.6,0c10.3,10.3,10.3,27.1,0,37.4C408.725,274.725,401.925,277.325,395.225,277.325z")), this._middle
                    }
                    get inner() {
                        return this._inner || (this._inner = document.createElementNS("http://www.w3.org/2000/svg", "path"), this._inner.setAttributeNS(null, "id", "inner"), this._inner.setAttributeNS(null, "d", "M323.625,348.825c-6.8,0-13.5-2.6-18.7-7.8c-15.4-15.4-36-23.9-57.8-23.9s-42.4,8.5-57.8,23.9c-10.3,10.3-27.1,10.3-37.4,0c-10.3-10.3-10.3-27.1,0-37.4c25.4-25.4,59.2-39.4,95.2-39.4s69.8,14,95.2,39.5c10.3,10.3,10.3,27.1,0,37.4C337.225,346.225,330.425,348.825,323.625,348.825z")), this._inner
                    }
                    blinkVideoQualityStatus(e) {
                        let t = e,
                            n = 1;
                        const s = setInterval((() => {
                            n -= .1, this.qualityText.style.opacity = String(Math.abs(2 * (n - .5))), n <= .1 && (0 == --t ? clearInterval(s) : n = 1)
                        }), 100 / e)
                    }
                    updateQpTooltip(e) {
                        var t;
                        this.videoEncoderAvgQP = e, e > this.redQP ? (this.color = "red", this.blinkVideoQualityStatus(2), this.statsText = `<div style="color: ${this.color}">Poor encoding quality</div>`, this.outer.setAttributeNS(null, "fill", "#3c3b40"), this.middle.setAttributeNS(null, "fill", "#3c3b40"), this.inner.setAttributeNS(null, "fill", this.color), this.dot.setAttributeNS(null, "fill", this.color)) : e > this.orangeQP ? (this.color = "orange", this.blinkVideoQualityStatus(1), this.statsText = `<div style="color: ${this.color}">Blocky encoding quality</div>`, this.outer.setAttributeNS(null, "fill", "#3c3b40"), this.middle.setAttributeNS(null, "fill", this.color), this.inner.setAttributeNS(null, "fill", this.color), this.dot.setAttributeNS(null, "fill", this.color)) : e <= 0 ? (this.color = "#b0b0b0", this.outer.setAttributeNS(null, "fill", "#3c3b40"), this.middle.setAttributeNS(null, "fill", "#3c3b40"), this.inner.setAttributeNS(null, "fill", "#3c3b40"), this.dot.setAttributeNS(null, "fill", "#3c3b40"), this.statsText = `<div style="color: ${this.color}">Not connected</div>`) : (this.color = "lime", this.qualityStatus.style.opacity = 1 == (null === (t = this.config) || void 0 === t ? void 0 : t.hideWhenGood) ? "0" : "1", this.statsText = `<div style="color: ${this.color}">Clear encoding quality</div>`, this.outer.setAttributeNS(null, "fill", this.color), this.middle.setAttributeNS(null, "fill", this.color), this.inner.setAttributeNS(null, "fill", this.color), this.dot.setAttributeNS(null, "fill", this.color)), this.qualityText.innerHTML = this.statsText
                    }
                }
                var N = n(952);
                class U {
                    constructor(e) {
                        this._setting = e
                    }
                    get setting() {
                        return this._setting
                    }
                    get rootElement() {
                        return this._rootElement || (this._rootElement = document.createElement("div")), this._rootElement
                    }
                }
                class B extends U {
                    constructor(e) {
                        super(e), this.label = e.label, this.flag = e.flag
                    }
                    get setting() {
                        return this._setting
                    }
                    get settingsTextElem() {
                        return this._settingsTextElem || (this._settingsTextElem = document.createElement("div"), this._settingsTextElem.innerText = this.setting._label, this._settingsTextElem.title = this.setting.description), this._settingsTextElem
                    }
                    get checkbox() {
                        return this._checkbox || (this._checkbox = document.createElement("input"), this._checkbox.type = "checkbox", this._checkbox.addEventListener("keypress", (e => {
                            e.stopPropagation()
                        })), this._checkbox.addEventListener("keyup", (e => {
                            e.stopPropagation()
                        })), this._checkbox.addEventListener("keydown", (e => {
                            e.stopPropagation()
                        }))), this._checkbox
                    }
                    get rootElement() {
                        if (!this._rootElement) {
                            this._rootElement = document.createElement("div"), this._rootElement.id = this.setting.id, this._rootElement.classList.add("setting"), this._rootElement.appendChild(this.settingsTextElem);
                            const e = document.createElement("label");
                            e.classList.add("tgl-switch"), this._rootElement.appendChild(e), this.checkbox.title = this.setting.description, this.checkbox.classList.add("tgl"), this.checkbox.classList.add("tgl-flat");
                            const t = document.createElement("div");
                            t.classList.add("tgl-slider"), e.appendChild(this.checkbox), e.appendChild(t), this.checkbox.addEventListener("change", (() => {
                                this.setting.flag !== this.checkbox.checked && (this.setting.flag = this.checkbox.checked, this.setting.updateURLParams())
                            }))
                        }
                        return this._rootElement
                    }
                    set flag(e) {
                        this.checkbox.checked = e
                    }
                    get flag() {
                        return this.checkbox.checked
                    }
                    set label(e) {
                        this.settingsTextElem.innerText = e
                    }
                    get label() {
                        return this.settingsTextElem.innerText
                    }
                    disable() {
                        this.checkbox.disabled = !0
                    }
                    enable() {
                        this.checkbox.disabled = !1
                    }
                }
                class W extends U {
                    constructor(e) {
                        super(e), this.label = this.setting.label, this.number = this.setting.number
                    }
                    get setting() {
                        return this._setting
                    }
                    get settingsTextElem() {
                        return this._settingsTextElem || (this._settingsTextElem = document.createElement("label"), this._settingsTextElem.innerText = this.setting.label, this._settingsTextElem.title = this.setting.description), this._settingsTextElem
                    }
                    get spinner() {
                        return this._spinner || (this._spinner = document.createElement("input"), this._spinner.type = "number", null != this.setting.min && (this._spinner.min = this.setting.min.toString()), null != this.setting.max && (this._spinner.max = this.setting.max.toString()), this._spinner.value = this.setting.number.toString(), this._spinner.title = this.setting.description, this._spinner.classList.add("form-control"), this.spinner.addEventListener("keypress", (e => {
                            e.stopPropagation()
                        })), this.spinner.addEventListener("keyup", (e => {
                            e.stopPropagation()
                        })), this.spinner.addEventListener("keydown", (e => {
                            e.stopPropagation()
                        }))), this._spinner
                    }
                    get rootElement() {
                        return this._rootElement || (this._rootElement = document.createElement("div"), this._rootElement.classList.add("setting"), this._rootElement.classList.add("form-group"), this._rootElement.appendChild(this.settingsTextElem), this._rootElement.appendChild(this.spinner), this.spinner.onchange = e => {
                            const t = e.target,
                                n = Number.parseFloat(t.value);
                            Number.isNaN(n) ? (i.Vy.Warning(`Could not parse value change into a valid number - value was ${t.value}, resetting value to ${this.setting.min}`), this.setting.number !== this.setting.min && (this.setting.number = this.setting.min)) : this.setting.number !== n && (this.setting.number = n, this.setting.updateURLParams())
                        }), this._rootElement
                    }
                    set number(e) {
                        this.spinner.value = this.setting.clamp(e).toString()
                    }
                    get number() {
                        return +this.spinner.value
                    }
                    set label(e) {
                        this.settingsTextElem.innerText = e
                    }
                    get label() {
                        return this.settingsTextElem.innerText
                    }
                    disable() {
                        this.spinner.disabled = !0
                    }
                    enable() {
                        this.spinner.disabled = !1
                    }
                }
                class z extends U {
                    constructor(e) {
                        super(e), this.label = this.setting.label, this.text = this.setting.text
                    }
                    get setting() {
                        return this._setting
                    }
                    get settingsTextElem() {
                        return this._settingsTextElem || (this._settingsTextElem = document.createElement("div"), this._settingsTextElem.innerText = this.setting.label, this._settingsTextElem.title = this.setting.description), this._settingsTextElem
                    }
                    get textbox() {
                        return this._textbox || (this._textbox = document.createElement("input"), this._textbox.classList.add("form-control"), this._textbox.type = "textbox"), this._textbox
                    }
                    get rootElement() {
                        if (!this._rootElement) {
                            this._rootElement = document.createElement("div"), this._rootElement.id = this.setting.id, this._rootElement.classList.add("setting"), this._rootElement.appendChild(this.settingsTextElem);
                            const e = document.createElement("label");
                            this._rootElement.appendChild(e), this.textbox.title = this.setting.description, e.appendChild(this.textbox), this.textbox.addEventListener("input", (e => {
                                this.setting.text !== this.textbox.value && (this.setting.text = this.textbox.value, this.setting.updateURLParams()), e.stopPropagation()
                            })), this.textbox.addEventListener("keypress", (e => {
                                e.stopPropagation()
                            })), this.textbox.addEventListener("keyup", (e => {
                                e.stopPropagation()
                            })), this.textbox.addEventListener("keydown", (e => {
                                e.stopPropagation()
                            }))
                        }
                        return this._rootElement
                    }
                    set text(e) {
                        this.textbox.value = e
                    }
                    get text() {
                        return this.textbox.value
                    }
                    set label(e) {
                        this.settingsTextElem.innerText = e
                    }
                    get label() {
                        return this.settingsTextElem.innerText
                    }
                    disable() {
                        this.textbox.disabled = !0
                    }
                    enable() {
                        this.textbox.disabled = !1
                    }
                }
                class H extends U {
                    constructor(e) {
                        super(e), this.label = this.setting.label, this.options = this.setting.options, this.selected = this.setting.selected
                    }
                    get setting() {
                        return this._setting
                    }
                    get selector() {
                        return this._selector || (this._selector = document.createElement("select"), this._selector.classList.add("form-control"), this._selector.classList.add("settings-option")), this._selector
                    }
                    get settingsTextElem() {
                        return this._settingsTextElem || (this._settingsTextElem = document.createElement("div"), this._settingsTextElem.innerText = this.setting.label, this._settingsTextElem.title = this.setting.description), this._settingsTextElem
                    }
                    set label(e) {
                        this.settingsTextElem.innerText = e
                    }
                    get label() {
                        return this.settingsTextElem.innerText
                    }
                    get rootElement() {
                        if (!this._rootElement) {
                            this._rootElement = document.createElement("div"), this._rootElement.id = this.setting.id, this._rootElement.classList.add("setting"), this._rootElement.classList.add("form-group"), this._rootElement.appendChild(this.settingsTextElem);
                            const e = document.createElement("label");
                            this._rootElement.appendChild(e), this.selector.title = this.setting.description, e.appendChild(this.selector), this.selector.onchange = () => {
                                this.setting.selected !== this.selector.value && (this.setting.selected = this.selector.value, this.setting.updateURLParams())
                            }, this.selector.addEventListener("keypress", (e => {
                                e.stopPropagation()
                            })), this.selector.addEventListener("keyup", (e => {
                                e.stopPropagation()
                            })), this.selector.addEventListener("keydown", (e => {
                                e.stopPropagation()
                            }))
                        }
                        return this._rootElement
                    }
                    set options(e) {
                        for (let e = this.selector.options.length - 1; e >= 0; e--) this.selector.remove(e);
                        e.forEach((e => {
                            const t = document.createElement("option");
                            t.value = e, t.innerHTML = e, this.selector.appendChild(t)
                        }))
                    }
                    get options() {
                        return [...this.selector.options].map((e => e.value))
                    }
                    set selected(e) {
                        const t = this.options.filter((t => -1 !== t.indexOf(e)));
                        t.length && (this.selector.value = t[0])
                    }
                    get selected() {
                        return this.selector.value
                    }
                    disable() {
                        this.selector.disabled = !0
                    }
                    enable() {
                        this.selector.disabled = !1
                    }
                }
                class j {
                    constructor(e) {
                        this.customFlags = new Map, this.flagsUi = new Map, this.numericParametersUi = new Map, this.textParametersUi = new Map, this.optionParametersUi = new Map, this.createCustomUISettings(e.useUrlParams), this.registerSettingsUIComponents(e)
                    }
                    createCustomUISettings(e) {
                        this.customFlags.set(w.LightMode, new N.T(w.LightMode, "Color Scheme: Dark Mode", "Page styling will be either light or dark", !1, e, ((e, t) => {
                            t.label = `Color Scheme: ${e?"Light":"Dark"} Mode`
                        })))
                    }
                    registerSettingsUIComponents(e) {
                        for (const t of e.getFlags()) this.flagsUi.set(t.id, new B(t));
                        for (const e of Array.from(this.customFlags.values())) this.flagsUi.set(e.id, new B(e));
                        for (const t of e.getTextSettings()) this.textParametersUi.set(t.id, new z(t));
                        for (const t of e.getNumericSettings()) this.numericParametersUi.set(t.id, new W(t));
                        for (const t of e.getOptionSettings()) this.optionParametersUi.set(t.id, new H(t))
                    }
                    buildSectionWithHeading(e, t) {
                        const n = document.createElement("section");
                        n.classList.add("settingsContainer");
                        const s = document.createElement("div");
                        return s.classList.add("settingsHeader"), s.classList.add("settings-text"), s.textContent = t, n.appendChild(s), e.appendChild(n), n
                    }
                    populateSettingsElement(e, t) {
                        if (x(t, E.PixelStreaming)) {
                            const n = this.buildSectionWithHeading(e, E.PixelStreaming);
                            k(t, s.gw.SignallingServerUrl) && this.addSettingText(n, this.textParametersUi.get(s.gw.SignallingServerUrl)), k(t, s.mY.StreamerId) && this.addSettingOption(n, this.optionParametersUi.get(s.mY.StreamerId)), k(t, s.iI.AutoConnect) && this.addSettingFlag(n, this.flagsUi.get(s.iI.AutoConnect)), k(t, s.iI.AutoPlayVideo) && this.addSettingFlag(n, this.flagsUi.get(s.iI.AutoPlayVideo)), k(t, s.iI.UseMic) && this.addSettingFlag(n, this.flagsUi.get(s.iI.UseMic)), k(t, s.iI.UseCamera) && this.addSettingFlag(n, this.flagsUi.get(s.iI.UseCamera)), k(t, s.iI.StartVideoMuted) && this.addSettingFlag(n, this.flagsUi.get(s.iI.StartVideoMuted)), k(t, s.iI.IsQualityController) && this.addSettingFlag(n, this.flagsUi.get(s.iI.IsQualityController)), k(t, s.iI.ForceMonoAudio) && this.addSettingFlag(n, this.flagsUi.get(s.iI.ForceMonoAudio)), k(t, s.iI.ForceTURN) && this.addSettingFlag(n, this.flagsUi.get(s.iI.ForceTURN)), k(t, s.iI.SuppressBrowserKeys) && this.addSettingFlag(n, this.flagsUi.get(s.iI.SuppressBrowserKeys)), k(t, s.iI.AFKDetection) && this.addSettingFlag(n, this.flagsUi.get(s.iI.AFKDetection)), k(t, s.iI.WaitForStreamer) && this.addSettingFlag(n, this.flagsUi.get(s.iI.WaitForStreamer)), k(t, s.k$.AFKTimeoutSecs) && this.addSettingNumeric(n, this.numericParametersUi.get(s.k$.AFKTimeoutSecs)), k(t, s.k$.AFKCountdownSecs) && this.addSettingNumeric(n, this.numericParametersUi.get(s.k$.AFKCountdownSecs)), k(t, s.k$.MaxReconnectAttempts) && this.addSettingNumeric(n, this.numericParametersUi.get(s.k$.MaxReconnectAttempts)), k(t, s.k$.StreamerAutoJoinInterval) && this.addSettingNumeric(n, this.numericParametersUi.get(s.k$.StreamerAutoJoinInterval)), k(t, s.k$.KeepaliveDelay) && this.addSettingNumeric(n, this.numericParametersUi.get(s.k$.KeepaliveDelay))
                        }
                        if (x(t, E.UI)) {
                            const n = this.buildSectionWithHeading(e, E.UI);
                            k(t, s.iI.MatchViewportResolution) && this.addSettingFlag(n, this.flagsUi.get(s.iI.MatchViewportResolution)), k(t, s.iI.HoveringMouseMode) && this.addSettingFlag(n, this.flagsUi.get(s.iI.HoveringMouseMode)), k(t, w.LightMode) && this.addSettingFlag(n, this.flagsUi.get(w.LightMode))
                        }
                        if (x(t, E.Input)) {
                            const n = this.buildSectionWithHeading(e, E.Input);
                            k(t, s.iI.KeyboardInput) && this.addSettingFlag(n, this.flagsUi.get(s.iI.KeyboardInput)), k(t, s.iI.MouseInput) && this.addSettingFlag(n, this.flagsUi.get(s.iI.MouseInput)), k(t, s.iI.FakeMouseWithTouches) && this.addSettingFlag(n, this.flagsUi.get(s.iI.FakeMouseWithTouches)), k(t, s.iI.TouchInput) && this.addSettingFlag(n, this.flagsUi.get(s.iI.TouchInput)), k(t, s.iI.GamepadInput) && this.addSettingFlag(n, this.flagsUi.get(s.iI.GamepadInput)), k(t, s.iI.XRControllerInput) && this.addSettingFlag(n, this.flagsUi.get(s.iI.XRControllerInput))
                        }
                        if (x(t, E.Encoder)) {
                            const n = this.buildSectionWithHeading(e, E.Encoder);
                            k(t, s.k$.CompatQualityMin) && this.addSettingNumeric(n, this.numericParametersUi.get(s.k$.CompatQualityMin)), k(t, s.k$.CompatQualityMax) && this.addSettingNumeric(n, this.numericParametersUi.get(s.k$.CompatQualityMax));
                            const i = this.optionParametersUi.get(s.mY.PreferredCodec);
                            k(t, s.mY.PreferredCodec) && this.addSettingOption(n, this.optionParametersUi.get(s.mY.PreferredCodec)), i && [...i.selector.options].map((e => e.value)).includes("Only available on Chrome") && i.disable(), k(t, s.mY.PreferredQuality) && this.addSettingOption(n, this.optionParametersUi.get(s.mY.PreferredQuality))
                        }
                        if (x(t, E.WebRTC)) {
                            const n = this.buildSectionWithHeading(e, E.WebRTC);
                            k(t, s.k$.WebRTCFPS) && this.addSettingNumeric(n, this.numericParametersUi.get(s.k$.WebRTCFPS)), k(t, s.k$.WebRTCMinBitrate) && this.addSettingNumeric(n, this.numericParametersUi.get(s.k$.WebRTCMinBitrate)), k(t, s.k$.WebRTCMaxBitrate) && this.addSettingNumeric(n, this.numericParametersUi.get(s.k$.WebRTCMaxBitrate))
                        }
                    }
                    addSettingText(e, t) {
                        t && (e.appendChild(t.rootElement), this.textParametersUi.set(t.setting.id, t))
                    }
                    addSettingFlag(e, t) {
                        t && (e.appendChild(t.rootElement), this.flagsUi.set(t.setting.id, t))
                    }
                    addSettingNumeric(e, t) {
                        t && (e.appendChild(t.rootElement), this.numericParametersUi.set(t.setting.id, t))
                    }
                    addSettingOption(e, t) {
                        t && (e.appendChild(t.rootElement), this.optionParametersUi.set(t.setting.id, t))
                    }
                    onSettingsChanged({
                        data: {
                            id: e,
                            target: t,
                            type: n
                        }
                    }) {
                        if ("flag" === n) {
                            const n = e,
                                s = t,
                                i = this.flagsUi.get(n);
                            i && (i.flag !== s.flag && (i.flag = s.flag), i.label !== s.label && (i.label = s.label))
                        } else if ("number" === n) {
                            const n = e,
                                s = t,
                                i = this.numericParametersUi.get(n);
                            i && (i.number !== s.number && (i.number = s.number), i.label !== s.label && (i.label = s.label))
                        } else if ("text" === n) {
                            const n = e,
                                s = t,
                                i = this.textParametersUi.get(n);
                            i && (i.text !== s.text && (i.text = s.text), i.label !== s.label && (i.label = s.label))
                        } else if ("option" === n) {
                            const n = e,
                                s = t,
                                i = this.optionParametersUi.get(n);
                            if (i) {
                                const e = i.options,
                                    t = s.options;
                                e.length === t.length && e.every((e => t.includes(e))) || (i.options = s.options), i.selected !== s.selected && (i.selected = s.selected), i.label !== s.label && (i.label = s.label)
                            }
                        }
                    }
                    addCustomFlagOnSettingChangedListener(e, t) {
                        this.customFlags.has(e) && (this.customFlags.get(e).onChange = t)
                    }
                    setCustomFlagLabel(e, t) {
                        this.customFlags.has(e) ? (this.customFlags.get(e).label = t, this.flagsUi.get(e).label = t) : i.Vy.Warning(`Cannot set label for flag called ${e} - it does not exist in the Config.flags map.`)
                    }
                    isCustomFlagEnabled(e) {
                        return this.customFlags.get(e).flag
                    }
                    disableSetting(e) {
                        var t, n, i, r;
                        (0, s.CR)(e) ? null === (t = this.flagsUi.get(e)) || void 0 === t || t.disable(): (0, s.tQ)(e) ? null === (n = this.numericParametersUi.get(e)) || void 0 === n || n.disable() : (0, s.B9)(e) ? null === (i = this.textParametersUi.get(e)) || void 0 === i || i.disable() : (0, s.Ri)(e) && (null === (r = this.optionParametersUi.get(e)) || void 0 === r || r.disable())
                    }
                    enableSetting(e) {
                        var t, n, i, r;
                        (0, s.CR)(e) ? null === (t = this.flagsUi.get(e)) || void 0 === t || t.enable(): (0, s.tQ)(e) ? null === (n = this.numericParametersUi.get(e)) || void 0 === n || n.enable() : (0, s.B9)(e) ? null === (i = this.textParametersUi.get(e)) || void 0 === i || i.enable() : (0, s.Ri)(e) && (null === (r = this.optionParametersUi.get(e)) || void 0 === r || r.enable())
                    }
                }
                class Q extends CustomEvent {
                    constructor(e) {
                        super("editConfirmed", {
                            detail: e,
                            bubbles: !0,
                            cancelable: !0
                        }), this.confirmedText = e
                    }
                }
                class $ {
                    constructor() {
                        this._rootElement = this.rootElement, this._events = new EventTarget
                    }
                    get events() {
                        return this._events
                    }
                    showModal(e) {
                        e && (e = e.replace(/\0/g, ""), this.textArea.value = e), this.textArea.focus(), this.textArea.selectionStart = this.textArea.value.length
                    }
                    get rootElement() {
                        return this._rootElement || (this._rootElement = document.createElement("div"), this._rootElement.classList.add("modal"), this._rootElement.appendChild(this.innerModal)), this._rootElement
                    }
                    get innerModal() {
                        return this._innerModal || (this._innerModal = document.createElement("div"), this._innerModal.classList.add("innerModal"), this._innerModal.appendChild(this.editTextHeading), this._innerModal.appendChild(this.textArea), this._innerModal.appendChild(this.modalBtnContainer)), this._innerModal
                    }
                    get editTextHeading() {
                        return this._editTextHeading || (this._editTextHeading = document.createElement("h2"), this._editTextHeading.innerText = "Edit Text"), this._editTextHeading
                    }
                    get textArea() {
                        return this._textArea || (this._textArea = document.createElement("textarea"), this._textArea.classList.add("form-control"), this._textArea.classList.add("modalTextArea"), this._textArea.title = "Edit Text Area", this._textArea.placeholder = "UE text widget value here...", this.textArea.addEventListener("keypress", (e => {
                            e.stopPropagation()
                        })), this.textArea.addEventListener("keyup", (e => {
                            e.stopPropagation()
                        })), this.textArea.addEventListener("keydown", (e => {
                            e.stopPropagation()
                        })), this.textArea.addEventListener("compositionend", (e => {
                            e.stopPropagation()
                        }))), this._textArea
                    }
                    get modalBtnContainer() {
                        return this._modalBtnContainer || (this._modalBtnContainer = document.createElement("div"), this._modalBtnContainer.classList.add("modalBtnContainer"), this._modalBtnContainer.appendChild(this.cancelBtn), this._modalBtnContainer.appendChild(this.confirmBtn)), this._modalBtnContainer
                    }
                    get cancelBtn() {
                        return this._cancelBtn || (this._cancelBtn = document.createElement("button"), this._cancelBtn.classList.add("btn-flat"), this._cancelBtn.innerText = "Cancel", this._cancelBtn.addEventListener("click", (e => {
                            this.rootElement.remove(), e.stopPropagation()
                        }))), this._cancelBtn
                    }
                    get confirmBtn() {
                        return this._confirmBtn || (this._confirmBtn = document.createElement("button"), this._confirmBtn.classList.add("btn-flat"), this._confirmBtn.innerText = "Confirm", this._confirmBtn.addEventListener("click", (e => {
                            this.events.dispatchEvent(new Q(this.textArea.value)), this.rootElement.remove(), e.stopPropagation()
                        }))), this._confirmBtn
                    }
                }
                class K {
                    constructor(e) {
                        this.editTextModal = null, this._options = e, this.stream = e.stream, this._uiFeatureElement = this.createUIFeaturesElement(), this._rootElement = this.createRootElement(this.stream, this._uiFeatureElement), this.onColorModeChanged = e.onColorModeChanged, this.configUI = new j(this.stream.config), this.createOverlays(), M(e.statsPanelConfig) && (this.statsPanel = new _(e.statsPanelConfig), this.uiFeaturesElement.appendChild(this.statsPanel.rootElement)), M(e.settingsPanelConfig) && (this.settingsPanel = new L, this.uiFeaturesElement.appendChild(this.settingsPanel.rootElement), this.configureSettings()), e.videoQpIndicatorConfig && e.videoQpIndicatorConfig.disableIndicator || (this.videoQpIndicator = new V(e.videoQpIndicatorConfig), this.uiFeaturesElement.appendChild(this.videoQpIndicator.rootElement)), this.createButtons(), this.registerCallbacks(), this.showConnectOrAutoConnectOverlays(), this.setColorMode(this.configUI.isCustomFlagEnabled(w.LightMode)), this.stream.config._addOnSettingChangedListener(s.iI.HideUI, (e => {
                            this._uiFeatureElement.style.visibility = e ? "hidden" : "visible"
                        })), this.stream.config.isFlagEnabled(s.iI.HideUI) && (this._uiFeatureElement.style.visibility = "hidden")
                    }
                    createOverlays() {
                        this.disconnectOverlay = new l(this.stream.videoElementParent), this.connectOverlay = new a(this.stream.videoElementParent), this.playOverlay = new c(this.stream.videoElementParent), this.infoOverlay = new h(this.stream.videoElementParent), this.errorOverlay = new u(this.stream.videoElementParent), this.afkOverlay = new m(this.stream.videoElementParent), this.disconnectOverlay.onAction((() => this.stream.reconnect())), this.connectOverlay.onAction((() => this.stream.connect())), this.playOverlay.onAction((() => this.stream.play()))
                    }
                    createButtons() {
                        const e = /iPhone/.test(navigator.userAgent),
                            t = /iPad/.test(navigator.userAgent) || /Macintosh/.test(navigator.userAgent) && "ontouchend" in document,
                            n = navigator.vendor && navigator.vendor.indexOf("Apple") > -1 && navigator.userAgent && -1 == navigator.userAgent.indexOf("CriOS") && -1 == navigator.userAgent.indexOf("FxiOS"),
                            s = e || !n && t;
                        void 0 === this._options.fullScreenControlsConfig && s && (this._options.fullScreenControlsConfig = {
                            creationMode: S.Disable
                        });
                        const i = {
                                statsButtonType: this._options.statsPanelConfig ? this._options.statsPanelConfig.visibilityButtonConfig : void 0,
                                settingsButtonType: this._options.settingsPanelConfig ? this._options.settingsPanelConfig.visibilityButtonConfig : void 0,
                                fullscreenButtonType: this._options.fullScreenControlsConfig,
                                xrIconType: this._options.xrControlsConfig,
                                hideControlsInFullscreen: this._options.hideControlsInFullscreen
                            },
                            r = new P(i);
                        this.uiFeaturesElement.appendChild(r.rootElement);
                        const o = this._options.fullScreenControlsConfig && this._options.fullScreenControlsConfig.creationMode === S.UseCustomElement ? new g(this._options.fullScreenControlsConfig.customElement) : r.fullscreenIcon;
                        o && (o.fullscreenElement = /iPad|iPhone|iPod/.test(navigator.userAgent) ? this.stream.videoElementParent.getElementsByTagName("video")[0] : this.rootElement);
                        const a = r.settingsIcon ? r.settingsIcon.rootElement : this._options.settingsPanelConfig.visibilityButtonConfig.customElement;
                        a && (a.onclick = () => this.settingsClicked()), this.settingsPanel && (this.settingsPanel.settingsCloseButton.onclick = () => this.settingsClicked());
                        const l = r.xrIcon ? r.xrIcon.rootElement : this._options.xrControlsConfig.creationMode === S.UseCustomElement ? this._options.xrControlsConfig.customElement : void 0;
                        l && (l.onclick = () => this.stream.toggleXR());
                        const c = r.statsIcon ? r.statsIcon.rootElement : this._options.statsPanelConfig.visibilityButtonConfig.customElement;
                        if (c && (c.onclick = () => this.statsClicked()), this.statsPanel && (this.statsPanel.statsCloseButton.onclick = () => this.statsClicked()), this.settingsPanel) {
                            const e = new I("Show FPS", "Toggle");
                            e.addOnClickListener((() => {
                                this.stream.requestShowFps()
                            }));
                            const t = new I("Restart Stream", "Restart");
                            t.addOnClickListener((() => {
                                this.stream.reconnect()
                            }));
                            const n = new I("Request keyframe", "Request");
                            n.addOnClickListener((() => {
                                this.stream.requestIframe()
                            }));
                            const s = this.configUI.buildSectionWithHeading(this.settingsPanel.settingsContentElement, "Commands");
                            s.appendChild(e.rootElement), s.appendChild(n.rootElement), s.appendChild(t.rootElement)
                        }
                    }
                    configureSettings() {
                        this.configUI.populateSettingsElement(this.settingsPanel.settingsContentElement, this._options.settingsPanelConfig), this.configUI.addCustomFlagOnSettingChangedListener(w.LightMode, (e => {
                            this.configUI.setCustomFlagLabel(w.LightMode, `Color Scheme: ${e?"Light":"Dark"} Mode`), this.setColorMode(e)
                        }))
                    }
                    registerCallbacks() {
                        this.stream.addEventListener("afkWarningActivate", (({
                            data: {
                                countDown: e,
                                dismissAfk: t
                            }
                        }) => this.showAfkOverlay(e, t))), this.stream.addEventListener("afkWarningUpdate", (({
                            data: {
                                countDown: e
                            }
                        }) => this.afkOverlay.updateCountdown(e))), this.stream.addEventListener("afkWarningDeactivate", (() => this.afkOverlay.hide())), this.stream.addEventListener("afkTimedOut", (() => this.afkOverlay.hide())), this.stream.addEventListener("videoEncoderAvgQP", (({
                            data: {
                                avgQP: e
                            }
                        }) => this.onVideoEncoderAvgQP(e))), this.stream.addEventListener("webRtcSdp", (() => this.onWebRtcSdp())), this.stream.addEventListener("webRtcAutoConnect", (() => this.onWebRtcAutoConnect())), this.stream.addEventListener("webRtcConnecting", (() => this.onWebRtcConnecting())), this.stream.addEventListener("webRtcConnected", (() => this.onWebRtcConnected())), this.stream.addEventListener("webRtcFailed", (() => this.onWebRtcFailed())), this.stream.addEventListener("webRtcDisconnected", (({
                            data: {
                                eventString: e,
                                allowClickToReconnect: t
                            }
                        }) => this.onDisconnect(e, t))), this.stream.addEventListener("videoInitialized", (() => this.onVideoInitialized())), this.stream.addEventListener("streamLoading", (() => this.onStreamLoading())), this.stream.addEventListener("playStreamError", (({
                            data: {
                                message: e
                            }
                        }) => this.onPlayStreamError(e))), this.stream.addEventListener("playStream", (() => this.onPlayStream())), this.stream.addEventListener("playStreamRejected", (({
                            data: {
                                reason: e
                            }
                        }) => this.onPlayStreamRejected(e))), this.stream.addEventListener("loadFreezeFrame", (({
                            data: {
                                shouldShowPlayOverlay: e
                            }
                        }) => this.onLoadFreezeFrame(e))), this.stream.addEventListener("statsReceived", (({
                            data: {
                                aggregatedStats: e
                            }
                        }) => this.onStatsReceived(e))), this.stream.addEventListener("latencyCalculated", (({
                            data: {
                                latencyInfo: e
                            }
                        }) => this.onLatencyUpdate(e))), this.stream.addEventListener("latencyTestResult", (({
                            data: {
                                latencyTimings: e
                            }
                        }) => this.onLatencyTestResults(e))), this.stream.addEventListener("dataChannelLatencyTestResult", (({
                            data: {
                                result: e
                            }
                        }) => this.onDataChannelLatencyTestResults(e))), this.stream.addEventListener("streamerListMessage", (({
                            data: {
                                messageStreamerList: e,
                                autoSelectedStreamerId: t,
                                wantedStreamerId: n
                            }
                        }) => this.handleStreamerListMessage(e, t, n))), this.stream.addEventListener("subscribeFailed", (({
                            data: {
                                message: e
                            }
                        }) => this.handleSubscribeFailedMessage(e))), this.stream.addEventListener("settingsChanged", (e => this.onSettingsChanged(e))), this.stream.addEventListener("playerCount", (({
                            data: {
                                count: e
                            }
                        }) => this.onPlayerCount(e))), this.stream.addEventListener("webRtcTCPRelayDetected", (() => i.Vy.Warning("Stream quailty degraded due to network enviroment, stream is relayed over TCP."))), this.stream.addEventListener("showOnScreenKeyboard", (e => {
                            if (!this.stream.config.isFlagEnabled(s.iI.UseModalForTextInput)) return;
                            const t = e.data;
                            t.showOnScreenKeyboard && this.showEditTextModal(t.contents)
                        }))
                    }
                    get rootElement() {
                        return this._rootElement || (this._rootElement = this.createRootElement(this.stream, this.uiFeaturesElement)), this._rootElement
                    }
                    createRootElement(e, t) {
                        const n = document.createElement("div");
                        if (n.id = "playerUI", n.classList.add("noselect"), void 0 === e) throw new Error("Could not create root element properly - pixelstreaming object was undefined. Are you calling this too early?");
                        if (void 0 === e.videoElementParent) throw new Error("Could not create root element properly - videoElementParent object was undefined. Are you calling this too early?");
                        if (void 0 === t) throw new Error("Could not create root element properly - uiFeaturesElement object was undefined. Are you calling this too early?");
                        return n.appendChild(e.videoElementParent), n.appendChild(t), n
                    }
                    get uiFeaturesElement() {
                        return this._uiFeatureElement || (this._uiFeatureElement = this.createUIFeaturesElement()), this._uiFeatureElement
                    }
                    createUIFeaturesElement() {
                        const e = document.createElement("div");
                        return e.id = "uiFeatures", e
                    }
                    showDisconnectOverlay(e) {
                        this.hideCurrentOverlay(), this.updateDisconnectOverlay(e), this.disconnectOverlay.show(), this.currentOverlay = this.disconnectOverlay
                    }
                    updateDisconnectOverlay(e) {
                        this.disconnectOverlay.update(e)
                    }
                    onDisconnectionAction() {
                        this.disconnectOverlay.activate()
                    }
                    hideCurrentOverlay() {
                        null != this.currentOverlay && (this.currentOverlay.hide(), this.currentOverlay = null)
                    }
                    showConnectOverlay() {
                        this.hideCurrentOverlay(), this.connectOverlay.show(), this.currentOverlay = this.connectOverlay
                    }
                    showPlayOverlay() {
                        this.hideCurrentOverlay(), this.playOverlay.show(), this.currentOverlay = this.playOverlay
                    }
                    showTextOverlay(e) {
                        this.hideCurrentOverlay(), this.infoOverlay.update(e), this.infoOverlay.show(), this.currentOverlay = this.infoOverlay
                    }
                    showErrorOverlay(e) {
                        this.hideCurrentOverlay(), this.errorOverlay.update(e), this.errorOverlay.show(), this.currentOverlay = this.errorOverlay
                    }
                    settingsClicked() {
                        var e;
                        null === (e = this.statsPanel) || void 0 === e || e.hide(), this.settingsPanel.toggleVisibility()
                    }
                    statsClicked() {
                        var e;
                        null === (e = this.settingsPanel) || void 0 === e || e.hide(), this.statsPanel.toggleVisibility()
                    }
                    onConnectAction() {
                        this.connectOverlay.activate()
                    }
                    onPlayAction() {
                        this.playOverlay.activate()
                    }
                    showAfkOverlay(e, t) {
                        this.hideCurrentOverlay(), this.afkOverlay.updateCountdown(e), this.afkOverlay.onAction((() => t())), this.afkOverlay.show(), this.currentOverlay = this.afkOverlay
                    }
                    showConnectOrAutoConnectOverlays() {
                        this.stream.config.isFlagEnabled(s.iI.AutoConnect) || this.showConnectOverlay()
                    }
                    onWebRtcAutoConnect() {
                        this.showTextOverlay("Auto Connecting Now")
                    }
                    onWebRtcSdp() {
                        this.showTextOverlay("WebRTC Connection Negotiated")
                    }
                    onStreamLoading() {
                        const e = document.createElement("span");
                        e.className = "visually-hidden", e.innerHTML = "Loading...";
                        const t = document.createElement("div");
                        t.id = "loading-spinner", t.className = "spinner-border ms-2", t.setAttribute("role", "status"), t.appendChild(e), this.showTextOverlay("Loading Stream " + t.outerHTML)
                    }
                    onDisconnect(e, t) {
                        var n;
                        const s = "Disconnected" + (e ? `: ${e}` : ".");
                        t ? this.showDisconnectOverlay(`${s} Click To Restart.`) : this.showErrorOverlay(s), null === (n = this.statsPanel) || void 0 === n || n.onDisconnect()
                    }
                    onWebRtcConnecting() {
                        this.showTextOverlay("Starting connection to server, please wait")
                    }
                    onWebRtcConnected() {
                        this.showTextOverlay("WebRTC connected, waiting for video")
                    }
                    onWebRtcFailed() {
                        this.showErrorOverlay("Unable to setup video")
                    }
                    onLoadFreezeFrame(e) {
                        !0 === e && (i.Vy.Info("showing play overlay"), this.showPlayOverlay())
                    }
                    onPlayStream() {
                        this.hideCurrentOverlay()
                    }
                    onPlayStreamError(e) {
                        this.showErrorOverlay(e)
                    }
                    onPlayStreamRejected(e) {
                        this.showPlayOverlay()
                    }
                    onVideoInitialized() {
                        var e;
                        this.stream.config.isFlagEnabled(s.iI.AutoPlayVideo) || this.showPlayOverlay(), null === (e = this.statsPanel) || void 0 === e || e.onVideoInitialized(this.stream)
                    }
                    onVideoEncoderAvgQP(e) {
                        this.videoQpIndicator && this.videoQpIndicator.updateQpTooltip(e)
                    }
                    onInitialSettings(e) {
                        var t;
                        e.PixelStreamingSettings && (null === (t = this.statsPanel) || void 0 === t || t.configure(e.PixelStreamingSettings))
                    }
                    onStatsReceived(e) {
                        var t;
                        null === (t = this.statsPanel) || void 0 === t || t.handleStats(e)
                    }
                    onLatencyUpdate(e) {
                        var t;
                        null === (t = this.statsPanel) || void 0 === t || t.handleLatencyInfo(e)
                    }
                    onLatencyTestResults(e) {
                        var t;
                        null === (t = this.statsPanel) || void 0 === t || t.latencyTest.handleTestResult(e)
                    }
                    onDataChannelLatencyTestResults(e) {
                        var t;
                        null === (t = this.statsPanel) || void 0 === t || t.dataChannelLatencyTest.handleTestResult(e)
                    }
                    onPlayerCount(e) {
                        var t;
                        null === (t = this.statsPanel) || void 0 === t || t.handlePlayerCount(e)
                    }
                    handleStreamerListMessage(e, t, n) {
                        const i = this.stream.config.isFlagEnabled(s.iI.WaitForStreamer),
                            r = this.stream.isReconnecting();
                        let o = null,
                            a = !0;
                        t || (i && n ? r ? (o = `Waiting for ${n} to become available.`, a = !1) : (o = `Gave up waiting for ${n} to become available. Click to try again`, e.ids.length > 0 && (o += " or select a streamer from the settings menu."), a = !0) : 0 == e.ids.length ? r ? (o = "Waiting for a streamer to become available.", a = !1) : (o = "No streamers available. Click to try again.", a = !0) : (o = "Multiple streamers available. Select one from the settings menu.", a = !1), a ? this.showDisconnectOverlay(o) : this.showTextOverlay(o))
                    }
                    handleSubscribeFailedMessage(e) {
                        this.showDisconnectOverlay(`Subscribe failed: "${e}" Click to try again`)
                    }
                    setColorMode(e) {
                        this.onColorModeChanged && this.onColorModeChanged(e)
                    }
                    showEditTextModal(e) {
                        var t;
                        null === (t = this.editTextModal) || void 0 === t || t.rootElement.remove(), this.editTextModal = new $, this.rootElement.append(this.editTextModal.rootElement), this.editTextModal.showModal(e), this.editTextModal.events.addEventListener("editConfirmed", (e => {
                            const t = e;
                            this.stream.sendTextboxEntry(t.confirmedText)
                        }))
                    }
                    onSettingsChanged(e) {
                        this.configUI.onSettingsChanged(e);
                        const {
                            data: {
                                id: t,
                                target: n,
                                type: i
                            }
                        } = e;
                        if (t == s.mY.PreferredQuality) {
                            [...this.stream.config.getSettingOption(s.mY.PreferredQuality).options].includes("Default") ? this.configUI.disableSetting(s.mY.PreferredQuality) : this.configUI.enableSetting(s.mY.PreferredQuality)
                        }
                    }
                }

                function G() {
                    return G = Object.assign ? Object.assign.bind() : function(e) {
                        for (var t = 1; t < arguments.length; t++) {
                            var n = arguments[t];
                            for (var s in n)({}).hasOwnProperty.call(n, s) && (e[s] = n[s])
                        }
                        return e
                    }, G.apply(null, arguments)
                }
                var q = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function(e) {
                    return typeof e
                } : function(e) {
                    return e && "function" == typeof Symbol && e.constructor === Symbol && e !== Symbol.prototype ? "symbol" : typeof e
                };
                const X = "object" === ("undefined" == typeof window ? "undefined" : q(window)) && "object" === ("undefined" == typeof document ? "undefined" : q(document)) && 9 === document.nodeType;

                function J(e) {
                    return J = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function(e) {
                        return typeof e
                    } : function(e) {
                        return e && "function" == typeof Symbol && e.constructor === Symbol && e !== Symbol.prototype ? "symbol" : typeof e
                    }, J(e)
                }

                function Y(e) {
                    var t = function(e, t) {
                        if ("object" != J(e) || !e) return e;
                        var n = e[Symbol.toPrimitive];
                        if (void 0 !== n) {
                            var s = n.call(e, t || "default");
                            if ("object" != J(s)) return s;
                            throw new TypeError("@@toPrimitive must return a primitive value.")
                        }
                        return ("string" === t ? String : Number)(e)
                    }(e, "string");
                    return "symbol" == J(t) ? t : t + ""
                }

                function Z(e, t) {
                    for (var n = 0; n < t.length; n++) {
                        var s = t[n];
                        s.enumerable = s.enumerable || !1, s.configurable = !0, "value" in s && (s.writable = !0), Object.defineProperty(e, Y(s.key), s)
                    }
                }

                function ee(e, t, n) {
                    return t && Z(e.prototype, t), n && Z(e, n), Object.defineProperty(e, "prototype", {
                        writable: !1
                    }), e
                }

                function te(e, t) {
                    return te = Object.setPrototypeOf ? Object.setPrototypeOf.bind() : function(e, t) {
                        return e.__proto__ = t, e
                    }, te(e, t)
                }

                function ne(e, t) {
                    e.prototype = Object.create(t.prototype), e.prototype.constructor = e, te(e, t)
                }

                function se(e) {
                    if (void 0 === e) throw new ReferenceError("this hasn't been initialised - super() hasn't been called");
                    return e
                }
                var ie = {}.constructor;

                function re(e) {
                    if (null == e || "object" != typeof e) return e;
                    if (Array.isArray(e)) return e.map(re);
                    if (e.constructor !== ie) return e;
                    var t = {};
                    for (var n in e) t[n] = re(e[n]);
                    return t
                }

                function oe(e, t, n) {
                    void 0 === e && (e = "unnamed");
                    var s = n.jss,
                        i = re(t),
                        r = s.plugins.onCreateRule(e, i, n);
                    return r || (e[0], null)
                }
                var ae = function(e, t) {
                        for (var n = "", s = 0; s < e.length && "!important" !== e[s]; s++) n && (n += t), n += e[s];
                        return n
                    },
                    le = function(e) {
                        if (!Array.isArray(e)) return e;
                        var t = "";
                        if (Array.isArray(e[0]))
                            for (var n = 0; n < e.length && "!important" !== e[n]; n++) t && (t += ", "), t += ae(e[n], " ");
                        else t = ae(e, ", ");
                        return "!important" === e[e.length - 1] && (t += " !important"), t
                    };

                function ce(e) {
                    return e && !1 === e.format ? {
                        linebreak: "",
                        space: ""
                    } : {
                        linebreak: "\n",
                        space: " "
                    }
                }

                function de(e, t) {
                    for (var n = "", s = 0; s < t; s++) n += "  ";
                    return n + e
                }

                function he(e, t, n) {
                    void 0 === n && (n = {});
                    var s = "";
                    if (!t) return s;
                    var i = n.indent,
                        r = void 0 === i ? 0 : i,
                        o = t.fallbacks;
                    !1 === n.format && (r = -1 / 0);
                    var a = ce(n),
                        l = a.linebreak,
                        c = a.space;
                    if (e && r++, o)
                        if (Array.isArray(o))
                            for (var d = 0; d < o.length; d++) {
                                var h = o[d];
                                for (var u in h) {
                                    var m = h[u];
                                    null != m && (s && (s += l), s += de(u + ":" + c + le(m) + ";", r))
                                }
                            } else
                                for (var p in o) {
                                    var g = o[p];
                                    null != g && (s && (s += l), s += de(p + ":" + c + le(g) + ";", r))
                                }
                    for (var f in t) {
                        var y = t[f];
                        null != y && "fallbacks" !== f && (s && (s += l), s += de(f + ":" + c + le(y) + ";", r))
                    }
                    return (s || n.allowEmpty) && e ? (s && (s = "" + l + s + l), de("" + e + c + "{" + s, --r) + de("}", r)) : s
                }
                var ue = /([[\].#*$><+~=|^:(),"'`\s])/g,
                    me = "undefined" != typeof CSS && CSS.escape,
                    pe = function(e) {
                        return me ? me(e) : e.replace(ue, "\\$1")
                    },
                    ge = function() {
                        function e(e, t, n) {
                            this.type = "style", this.isProcessed = !1;
                            var s = n.sheet,
                                i = n.Renderer;
                            this.key = e, this.options = n, this.style = t, s ? this.renderer = s.renderer : i && (this.renderer = new i)
                        }
                        return e.prototype.prop = function(e, t, n) {
                            if (void 0 === t) return this.style[e];
                            var s = !!n && n.force;
                            if (!s && this.style[e] === t) return this;
                            var i = t;
                            n && !1 === n.process || (i = this.options.jss.plugins.onChangeValue(t, e, this));
                            var r = null == i || !1 === i,
                                o = e in this.style;
                            if (r && !o && !s) return this;
                            var a = r && o;
                            if (a ? delete this.style[e] : this.style[e] = i, this.renderable && this.renderer) return a ? this.renderer.removeProperty(this.renderable, e) : this.renderer.setProperty(this.renderable, e, i), this;
                            var l = this.options.sheet;
                            return l && l.attached, this
                        }, e
                    }(),
                    fe = function(e) {
                        function t(t, n, s) {
                            var i;
                            i = e.call(this, t, n, s) || this;
                            var r = s.selector,
                                o = s.scoped,
                                a = s.sheet,
                                l = s.generateId;
                            return r ? i.selectorText = r : !1 !== o && (i.id = l(se(se(i)), a), i.selectorText = "." + pe(i.id)), i
                        }
                        ne(t, e);
                        var n = t.prototype;
                        return n.applyTo = function(e) {
                            var t = this.renderer;
                            if (t) {
                                var n = this.toJSON();
                                for (var s in n) t.setProperty(e, s, n[s])
                            }
                            return this
                        }, n.toJSON = function() {
                            var e = {};
                            for (var t in this.style) {
                                var n = this.style[t];
                                "object" != typeof n ? e[t] = n : Array.isArray(n) && (e[t] = le(n))
                            }
                            return e
                        }, n.toString = function(e) {
                            var t = this.options.sheet,
                                n = !!t && t.options.link ? G({}, e, {
                                    allowEmpty: !0
                                }) : e;
                            return he(this.selectorText, this.style, n)
                        }, ee(t, [{
                            key: "selector",
                            set: function(e) {
                                if (e !== this.selectorText) {
                                    this.selectorText = e;
                                    var t = this.renderer,
                                        n = this.renderable;
                                    if (n && t) t.setSelector(n, e) || t.replaceRule(n, this)
                                }
                            },
                            get: function() {
                                return this.selectorText
                            }
                        }]), t
                    }(ge),
                    ye = {
                        onCreateRule: function(e, t, n) {
                            return "@" === e[0] || n.parent && "keyframes" === n.parent.type ? null : new fe(e, t, n)
                        }
                    },
                    ve = {
                        indent: 1,
                        children: !0
                    },
                    be = /@([\w-]+)/,
                    Se = function() {
                        function e(e, t, n) {
                            this.type = "conditional", this.isProcessed = !1, this.key = e;
                            var s = e.match(be);
                            for (var i in this.at = s ? s[1] : "unknown", this.query = n.name || "@" + this.at, this.options = n, this.rules = new je(G({}, n, {
                                    parent: this
                                })), t) this.rules.add(i, t[i]);
                            this.rules.process()
                        }
                        var t = e.prototype;
                        return t.getRule = function(e) {
                            return this.rules.get(e)
                        }, t.indexOf = function(e) {
                            return this.rules.indexOf(e)
                        }, t.addRule = function(e, t, n) {
                            var s = this.rules.add(e, t, n);
                            return s ? (this.options.jss.plugins.onProcessRule(s), s) : null
                        }, t.replaceRule = function(e, t, n) {
                            var s = this.rules.replace(e, t, n);
                            return s && this.options.jss.plugins.onProcessRule(s), s
                        }, t.toString = function(e) {
                            void 0 === e && (e = ve);
                            var t = ce(e).linebreak;
                            if (null == e.indent && (e.indent = ve.indent), null == e.children && (e.children = ve.children), !1 === e.children) return this.query + " {}";
                            var n = this.rules.toString(e);
                            return n ? this.query + " {" + t + n + t + "}" : ""
                        }, e
                    }(),
                    Ce = /@container|@media|@supports\s+/,
                    we = {
                        onCreateRule: function(e, t, n) {
                            return Ce.test(e) ? new Se(e, t, n) : null
                        }
                    },
                    Ee = {
                        indent: 1,
                        children: !0
                    },
                    Te = /@keyframes\s+([\w-]+)/,
                    Me = function() {
                        function e(e, t, n) {
                            this.type = "keyframes", this.at = "@keyframes", this.isProcessed = !1;
                            var s = e.match(Te);
                            s && s[1] ? this.name = s[1] : this.name = "noname", this.key = this.type + "-" + this.name, this.options = n;
                            var i = n.scoped,
                                r = n.sheet,
                                o = n.generateId;
                            for (var a in this.id = !1 === i ? this.name : pe(o(this, r)), this.rules = new je(G({}, n, {
                                    parent: this
                                })), t) this.rules.add(a, t[a], G({}, n, {
                                parent: this
                            }));
                            this.rules.process()
                        }
                        return e.prototype.toString = function(e) {
                            void 0 === e && (e = Ee);
                            var t = ce(e).linebreak;
                            if (null == e.indent && (e.indent = Ee.indent), null == e.children && (e.children = Ee.children), !1 === e.children) return this.at + " " + this.id + " {}";
                            var n = this.rules.toString(e);
                            return n && (n = "" + t + n + t), this.at + " " + this.id + " {" + n + "}"
                        }, e
                    }(),
                    xe = /@keyframes\s+/,
                    ke = /\$([\w-]+)/g,
                    Re = function(e, t) {
                        return "string" == typeof e ? e.replace(ke, (function(e, n) {
                            return n in t ? t[n] : e
                        })) : e
                    },
                    Pe = function(e, t, n) {
                        var s = e[t],
                            i = Re(s, n);
                        i !== s && (e[t] = i)
                    },
                    Ie = {
                        onCreateRule: function(e, t, n) {
                            return "string" == typeof e && xe.test(e) ? new Me(e, t, n) : null
                        },
                        onProcessStyle: function(e, t, n) {
                            return "style" === t.type && n ? ("animation-name" in e && Pe(e, "animation-name", n.keyframes), "animation" in e && Pe(e, "animation", n.keyframes), e) : e
                        },
                        onChangeValue: function(e, t, n) {
                            var s = n.options.sheet;
                            if (!s) return e;
                            switch (t) {
                                case "animation":
                                case "animation-name":
                                    return Re(e, s.keyframes);
                                default:
                                    return e
                            }
                        }
                    },
                    Le = function(e) {
                        function t() {
                            return e.apply(this, arguments) || this
                        }
                        return ne(t, e), t.prototype.toString = function(e) {
                            var t = this.options.sheet,
                                n = !!t && t.options.link ? G({}, e, {
                                    allowEmpty: !0
                                }) : e;
                            return he(this.key, this.style, n)
                        }, t
                    }(ge),
                    Oe = {
                        onCreateRule: function(e, t, n) {
                            return n.parent && "keyframes" === n.parent.type ? new Le(e, t, n) : null
                        }
                    },
                    Fe = function() {
                        function e(e, t, n) {
                            this.type = "font-face", this.at = "@font-face", this.isProcessed = !1, this.key = e, this.style = t, this.options = n
                        }
                        return e.prototype.toString = function(e) {
                            var t = ce(e).linebreak;
                            if (Array.isArray(this.style)) {
                                for (var n = "", s = 0; s < this.style.length; s++) n += he(this.at, this.style[s]), this.style[s + 1] && (n += t);
                                return n
                            }
                            return he(this.at, this.style, e)
                        }, e
                    }(),
                    De = /@font-face/,
                    Ae = {
                        onCreateRule: function(e, t, n) {
                            return De.test(e) ? new Fe(e, t, n) : null
                        }
                    },
                    _e = function() {
                        function e(e, t, n) {
                            this.type = "viewport", this.at = "@viewport", this.isProcessed = !1, this.key = e, this.style = t, this.options = n
                        }
                        return e.prototype.toString = function(e) {
                            return he(this.key, this.style, e)
                        }, e
                    }(),
                    Ve = {
                        onCreateRule: function(e, t, n) {
                            return "@viewport" === e || "@-ms-viewport" === e ? new _e(e, t, n) : null
                        }
                    },
                    Ne = function() {
                        function e(e, t, n) {
                            this.type = "simple", this.isProcessed = !1, this.key = e, this.value = t, this.options = n
                        }
                        return e.prototype.toString = function(e) {
                            if (Array.isArray(this.value)) {
                                for (var t = "", n = 0; n < this.value.length; n++) t += this.key + " " + this.value[n] + ";", this.value[n + 1] && (t += "\n");
                                return t
                            }
                            return this.key + " " + this.value + ";"
                        }, e
                    }(),
                    Ue = {
                        "@charset": !0,
                        "@import": !0,
                        "@namespace": !0
                    },
                    Be = {
                        onCreateRule: function(e, t, n) {
                            return e in Ue ? new Ne(e, t, n) : null
                        }
                    },
                    We = [ye, we, Ie, Oe, Ae, Ve, Be],
                    ze = {
                        process: !0
                    },
                    He = {
                        force: !0,
                        process: !0
                    },
                    je = function() {
                        function e(e) {
                            this.map = {}, this.raw = {}, this.index = [], this.counter = 0, this.options = e, this.classes = e.classes, this.keyframes = e.keyframes
                        }
                        var t = e.prototype;
                        return t.add = function(e, t, n) {
                            var s = this.options,
                                i = s.parent,
                                r = s.sheet,
                                o = s.jss,
                                a = s.Renderer,
                                l = s.generateId,
                                c = s.scoped,
                                d = G({
                                    classes: this.classes,
                                    parent: i,
                                    sheet: r,
                                    jss: o,
                                    Renderer: a,
                                    generateId: l,
                                    scoped: c,
                                    name: e,
                                    keyframes: this.keyframes,
                                    selector: void 0
                                }, n),
                                h = e;
                            e in this.raw && (h = e + "-d" + this.counter++), this.raw[h] = t, h in this.classes && (d.selector = "." + pe(this.classes[h]));
                            var u = oe(h, t, d);
                            if (!u) return null;
                            this.register(u);
                            var m = void 0 === d.index ? this.index.length : d.index;
                            return this.index.splice(m, 0, u), u
                        }, t.replace = function(e, t, n) {
                            var s = this.get(e),
                                i = this.index.indexOf(s);
                            s && this.remove(s);
                            var r = n;
                            return -1 !== i && (r = G({}, n, {
                                index: i
                            })), this.add(e, t, r)
                        }, t.get = function(e) {
                            return this.map[e]
                        }, t.remove = function(e) {
                            this.unregister(e), delete this.raw[e.key], this.index.splice(this.index.indexOf(e), 1)
                        }, t.indexOf = function(e) {
                            return this.index.indexOf(e)
                        }, t.process = function() {
                            var e = this.options.jss.plugins;
                            this.index.slice(0).forEach(e.onProcessRule, e)
                        }, t.register = function(e) {
                            this.map[e.key] = e, e instanceof fe ? (this.map[e.selector] = e, e.id && (this.classes[e.key] = e.id)) : e instanceof Me && this.keyframes && (this.keyframes[e.name] = e.id)
                        }, t.unregister = function(e) {
                            delete this.map[e.key], e instanceof fe ? (delete this.map[e.selector], delete this.classes[e.key]) : e instanceof Me && delete this.keyframes[e.name]
                        }, t.update = function() {
                            var e, t, n;
                            if ("string" == typeof(arguments.length <= 0 ? void 0 : arguments[0]) ? (e = arguments.length <= 0 ? void 0 : arguments[0], t = arguments.length <= 1 ? void 0 : arguments[1], n = arguments.length <= 2 ? void 0 : arguments[2]) : (t = arguments.length <= 0 ? void 0 : arguments[0], n = arguments.length <= 1 ? void 0 : arguments[1], e = null), e) this.updateOne(this.get(e), t, n);
                            else
                                for (var s = 0; s < this.index.length; s++) this.updateOne(this.index[s], t, n)
                        }, t.updateOne = function(t, n, s) {
                            void 0 === s && (s = ze);
                            var i = this.options,
                                r = i.jss.plugins,
                                o = i.sheet;
                            if (t.rules instanceof e) t.rules.update(n, s);
                            else {
                                var a = t.style;
                                if (r.onUpdate(n, t, o, s), s.process && a && a !== t.style) {
                                    for (var l in r.onProcessStyle(t.style, t, o), t.style) {
                                        var c = t.style[l];
                                        c !== a[l] && t.prop(l, c, He)
                                    }
                                    for (var d in a) {
                                        var h = t.style[d],
                                            u = a[d];
                                        null == h && h !== u && t.prop(d, null, He)
                                    }
                                }
                            }
                        }, t.toString = function(e) {
                            for (var t = "", n = this.options.sheet, s = !!n && n.options.link, i = ce(e).linebreak, r = 0; r < this.index.length; r++) {
                                var o = this.index[r].toString(e);
                                (o || s) && (t && (t += i), t += o)
                            }
                            return t
                        }, e
                    }(),
                    Qe = function() {
                        function e(e, t) {
                            for (var n in this.attached = !1, this.deployed = !1, this.classes = {}, this.keyframes = {}, this.options = G({}, t, {
                                    sheet: this,
                                    parent: this,
                                    classes: this.classes,
                                    keyframes: this.keyframes
                                }), t.Renderer && (this.renderer = new t.Renderer(this)), this.rules = new je(this.options), e) this.rules.add(n, e[n]);
                            this.rules.process()
                        }
                        var t = e.prototype;
                        return t.attach = function() {
                            return this.attached || (this.renderer && this.renderer.attach(), this.attached = !0, this.deployed || this.deploy()), this
                        }, t.detach = function() {
                            return this.attached ? (this.renderer && this.renderer.detach(), this.attached = !1, this) : this
                        }, t.addRule = function(e, t, n) {
                            var s = this.queue;
                            this.attached && !s && (this.queue = []);
                            var i = this.rules.add(e, t, n);
                            return i ? (this.options.jss.plugins.onProcessRule(i), this.attached ? this.deployed ? (s ? s.push(i) : (this.insertRule(i), this.queue && (this.queue.forEach(this.insertRule, this), this.queue = void 0)), i) : i : (this.deployed = !1, i)) : null
                        }, t.replaceRule = function(e, t, n) {
                            var s = this.rules.get(e);
                            if (!s) return this.addRule(e, t, n);
                            var i = this.rules.replace(e, t, n);
                            return i && this.options.jss.plugins.onProcessRule(i), this.attached ? this.deployed ? (this.renderer && (i ? s.renderable && this.renderer.replaceRule(s.renderable, i) : this.renderer.deleteRule(s)), i) : i : (this.deployed = !1, i)
                        }, t.insertRule = function(e) {
                            this.renderer && this.renderer.insertRule(e)
                        }, t.addRules = function(e, t) {
                            var n = [];
                            for (var s in e) {
                                var i = this.addRule(s, e[s], t);
                                i && n.push(i)
                            }
                            return n
                        }, t.getRule = function(e) {
                            return this.rules.get(e)
                        }, t.deleteRule = function(e) {
                            var t = "object" == typeof e ? e : this.rules.get(e);
                            return !(!t || this.attached && !t.renderable) && (this.rules.remove(t), !(this.attached && t.renderable && this.renderer) || this.renderer.deleteRule(t.renderable))
                        }, t.indexOf = function(e) {
                            return this.rules.indexOf(e)
                        }, t.deploy = function() {
                            return this.renderer && this.renderer.deploy(), this.deployed = !0, this
                        }, t.update = function() {
                            var e;
                            return (e = this.rules).update.apply(e, arguments), this
                        }, t.updateOne = function(e, t, n) {
                            return this.rules.updateOne(e, t, n), this
                        }, t.toString = function(e) {
                            return this.rules.toString(e)
                        }, e
                    }(),
                    $e = function() {
                        function e() {
                            this.plugins = {
                                internal: [],
                                external: []
                            }, this.registry = {}
                        }
                        var t = e.prototype;
                        return t.onCreateRule = function(e, t, n) {
                            for (var s = 0; s < this.registry.onCreateRule.length; s++) {
                                var i = this.registry.onCreateRule[s](e, t, n);
                                if (i) return i
                            }
                            return null
                        }, t.onProcessRule = function(e) {
                            if (!e.isProcessed) {
                                for (var t = e.options.sheet, n = 0; n < this.registry.onProcessRule.length; n++) this.registry.onProcessRule[n](e, t);
                                e.style && this.onProcessStyle(e.style, e, t), e.isProcessed = !0
                            }
                        }, t.onProcessStyle = function(e, t, n) {
                            for (var s = 0; s < this.registry.onProcessStyle.length; s++) t.style = this.registry.onProcessStyle[s](t.style, t, n)
                        }, t.onProcessSheet = function(e) {
                            for (var t = 0; t < this.registry.onProcessSheet.length; t++) this.registry.onProcessSheet[t](e)
                        }, t.onUpdate = function(e, t, n, s) {
                            for (var i = 0; i < this.registry.onUpdate.length; i++) this.registry.onUpdate[i](e, t, n, s)
                        }, t.onChangeValue = function(e, t, n) {
                            for (var s = e, i = 0; i < this.registry.onChangeValue.length; i++) s = this.registry.onChangeValue[i](s, t, n);
                            return s
                        }, t.use = function(e, t) {
                            void 0 === t && (t = {
                                queue: "external"
                            });
                            var n = this.plugins[t.queue]; - 1 === n.indexOf(e) && (n.push(e), this.registry = [].concat(this.plugins.external, this.plugins.internal).reduce((function(e, t) {
                                for (var n in t) n in e && e[n].push(t[n]);
                                return e
                            }), {
                                onCreateRule: [],
                                onProcessRule: [],
                                onProcessStyle: [],
                                onProcessSheet: [],
                                onChangeValue: [],
                                onUpdate: []
                            }))
                        }, e
                    }(),
                    Ke = function() {
                        function e() {
                            this.registry = []
                        }
                        var t = e.prototype;
                        return t.add = function(e) {
                            var t = this.registry,
                                n = e.options.index;
                            if (-1 === t.indexOf(e))
                                if (0 === t.length || n >= this.index) t.push(e);
                                else
                                    for (var s = 0; s < t.length; s++)
                                        if (t[s].options.index > n) return void t.splice(s, 0, e)
                        }, t.reset = function() {
                            this.registry = []
                        }, t.remove = function(e) {
                            var t = this.registry.indexOf(e);
                            this.registry.splice(t, 1)
                        }, t.toString = function(e) {
                            for (var t = void 0 === e ? {} : e, n = t.attached, s = function(e, t) {
                                    if (null == e) return {};
                                    var n = {};
                                    for (var s in e)
                                        if ({}.hasOwnProperty.call(e, s)) {
                                            if (-1 !== t.indexOf(s)) continue;
                                            n[s] = e[s]
                                        } return n
                                }(t, ["attached"]), i = ce(s).linebreak, r = "", o = 0; o < this.registry.length; o++) {
                                var a = this.registry[o];
                                null != n && a.attached !== n || (r && (r += i), r += a.toString(s))
                            }
                            return r
                        }, ee(e, [{
                            key: "index",
                            get: function() {
                                return 0 === this.registry.length ? 0 : this.registry[this.registry.length - 1].options.index
                            }
                        }]), e
                    }(),
                    Ge = new Ke,
                    qe = "undefined" != typeof globalThis ? globalThis : "undefined" != typeof window && window.Math === Math ? window : "undefined" != typeof self && self.Math === Math ? self : Function("return this")(),
                    Xe = "2f1acc6c3a606b082e5eef5e54414ffb";
                null == qe[Xe] && (qe[Xe] = 0);
                var Je = qe[Xe]++,
                    Ye = function(e) {
                        void 0 === e && (e = {});
                        var t = 0;
                        return function(n, s) {
                            t += 1;
                            var i = "",
                                r = "";
                            return s && (s.options.classNamePrefix && (r = s.options.classNamePrefix), null != s.options.jss.id && (i = String(s.options.jss.id))), e.minify ? "" + (r || "c") + Je + i + t : r + n.key + "-" + Je + (i ? "-" + i : "") + "-" + t
                        }
                    },
                    Ze = function(e) {
                        var t;
                        return function() {
                            return t || (t = e()), t
                        }
                    },
                    et = function(e, t) {
                        try {
                            return e.attributeStyleMap ? e.attributeStyleMap.get(t) : e.style.getPropertyValue(t)
                        } catch (e) {
                            return ""
                        }
                    },
                    tt = function(e, t, n) {
                        try {
                            var s = n;
                            if (Array.isArray(n) && (s = le(n)), e.attributeStyleMap) e.attributeStyleMap.set(t, s);
                            else {
                                var i = s ? s.indexOf("!important") : -1,
                                    r = i > -1 ? s.substr(0, i - 1) : s;
                                e.style.setProperty(t, r, i > -1 ? "important" : "")
                            }
                        } catch (e) {
                            return !1
                        }
                        return !0
                    },
                    nt = function(e, t) {
                        try {
                            e.attributeStyleMap ? e.attributeStyleMap.delete(t) : e.style.removeProperty(t)
                        } catch (e) {}
                    },
                    st = function(e, t) {
                        return e.selectorText = t, e.selectorText === t
                    },
                    it = Ze((function() {
                        return document.querySelector("head")
                    }));

                function rt(e) {
                    var t = Ge.registry;
                    if (t.length > 0) {
                        var n = function(e, t) {
                            for (var n = 0; n < e.length; n++) {
                                var s = e[n];
                                if (s.attached && s.options.index > t.index && s.options.insertionPoint === t.insertionPoint) return s
                            }
                            return null
                        }(t, e);
                        if (n && n.renderer) return {
                            parent: n.renderer.element.parentNode,
                            node: n.renderer.element
                        };
                        if (n = function(e, t) {
                                for (var n = e.length - 1; n >= 0; n--) {
                                    var s = e[n];
                                    if (s.attached && s.options.insertionPoint === t.insertionPoint) return s
                                }
                                return null
                            }(t, e), n && n.renderer) return {
                            parent: n.renderer.element.parentNode,
                            node: n.renderer.element.nextSibling
                        }
                    }
                    var s = e.insertionPoint;
                    if (s && "string" == typeof s) {
                        var i = function(e) {
                            for (var t = it(), n = 0; n < t.childNodes.length; n++) {
                                var s = t.childNodes[n];
                                if (8 === s.nodeType && s.nodeValue.trim() === e) return s
                            }
                            return null
                        }(s);
                        if (i) return {
                            parent: i.parentNode,
                            node: i.nextSibling
                        }
                    }
                    return !1
                }
                var ot, at = Ze((function() {
                        var e = document.querySelector('meta[property="csp-nonce"]');
                        return e ? e.getAttribute("content") : null
                    })),
                    lt = function(e, t, n) {
                        try {
                            "insertRule" in e ? e.insertRule(t, n) : "appendRule" in e && e.appendRule(t)
                        } catch (e) {
                            return !1
                        }
                        return e.cssRules[n]
                    },
                    ct = function(e, t) {
                        var n = e.cssRules.length;
                        return void 0 === t || t > n ? n : t
                    },
                    dt = function() {
                        function e(e) {
                            this.getPropertyValue = et, this.setProperty = tt, this.removeProperty = nt, this.setSelector = st, this.hasInsertedRules = !1, this.cssRules = [], e && Ge.add(e), this.sheet = e;
                            var t, n = this.sheet ? this.sheet.options : {},
                                s = n.media,
                                i = n.meta,
                                r = n.element;
                            this.element = r || ((t = document.createElement("style")).textContent = "\n", t), this.element.setAttribute("data-jss", ""), s && this.element.setAttribute("media", s), i && this.element.setAttribute("data-meta", i);
                            var o = at();
                            o && this.element.setAttribute("nonce", o)
                        }
                        var t = e.prototype;
                        return t.attach = function() {
                            if (!this.element.parentNode && this.sheet) {
                                ! function(e, t) {
                                    var n = t.insertionPoint,
                                        s = rt(t);
                                    if (!1 !== s && s.parent) s.parent.insertBefore(e, s.node);
                                    else if (n && "number" == typeof n.nodeType) {
                                        var i = n,
                                            r = i.parentNode;
                                        r && r.insertBefore(e, i.nextSibling)
                                    } else it().appendChild(e)
                                }(this.element, this.sheet.options);
                                var e = Boolean(this.sheet && this.sheet.deployed);
                                this.hasInsertedRules && e && (this.hasInsertedRules = !1, this.deploy())
                            }
                        }, t.detach = function() {
                            if (this.sheet) {
                                var e = this.element.parentNode;
                                e && e.removeChild(this.element), this.sheet.options.link && (this.cssRules = [], this.element.textContent = "\n")
                            }
                        }, t.deploy = function() {
                            var e = this.sheet;
                            e && (e.options.link ? this.insertRules(e.rules) : this.element.textContent = "\n" + e.toString() + "\n")
                        }, t.insertRules = function(e, t) {
                            for (var n = 0; n < e.index.length; n++) this.insertRule(e.index[n], n, t)
                        }, t.insertRule = function(e, t, n) {
                            if (void 0 === n && (n = this.element.sheet), e.rules) {
                                var s = e,
                                    i = n;
                                if ("conditional" === e.type || "keyframes" === e.type) {
                                    var r = ct(n, t);
                                    if (!1 === (i = lt(n, s.toString({
                                            children: !1
                                        }), r))) return !1;
                                    this.refCssRule(e, r, i)
                                }
                                return this.insertRules(s.rules, i), i
                            }
                            var o = e.toString();
                            if (!o) return !1;
                            var a = ct(n, t),
                                l = lt(n, o, a);
                            return !1 !== l && (this.hasInsertedRules = !0, this.refCssRule(e, a, l), l)
                        }, t.refCssRule = function(e, t, n) {
                            e.renderable = n, e.options.parent instanceof Qe && this.cssRules.splice(t, 0, n)
                        }, t.deleteRule = function(e) {
                            var t = this.element.sheet,
                                n = this.indexOf(e);
                            return -1 !== n && (t.deleteRule(n), this.cssRules.splice(n, 1), !0)
                        }, t.indexOf = function(e) {
                            return this.cssRules.indexOf(e)
                        }, t.replaceRule = function(e, t) {
                            var n = this.indexOf(e);
                            return -1 !== n && (this.element.sheet.deleteRule(n), this.cssRules.splice(n, 1), this.insertRule(t, n))
                        }, t.getRules = function() {
                            return this.element.sheet.cssRules
                        }, e
                    }(),
                    ht = 0,
                    ut = function() {
                        function e(e) {
                            this.id = ht++, this.version = "10.10.0", this.plugins = new $e, this.options = {
                                id: {
                                    minify: !1
                                },
                                createGenerateId: Ye,
                                Renderer: X ? dt : null,
                                plugins: []
                            }, this.generateId = Ye({
                                minify: !1
                            });
                            for (var t = 0; t < We.length; t++) this.plugins.use(We[t], {
                                queue: "internal"
                            });
                            this.setup(e)
                        }
                        var t = e.prototype;
                        return t.setup = function(e) {
                            return void 0 === e && (e = {}), e.createGenerateId && (this.options.createGenerateId = e.createGenerateId), e.id && (this.options.id = G({}, this.options.id, e.id)), (e.createGenerateId || e.id) && (this.generateId = this.options.createGenerateId(this.options.id)), null != e.insertionPoint && (this.options.insertionPoint = e.insertionPoint), "Renderer" in e && (this.options.Renderer = e.Renderer), e.plugins && this.use.apply(this, e.plugins), this
                        }, t.createStyleSheet = function(e, t) {
                            void 0 === t && (t = {});
                            var n = t.index;
                            "number" != typeof n && (n = 0 === Ge.index ? 0 : Ge.index + 1);
                            var s = new Qe(e, G({}, t, {
                                jss: this,
                                generateId: t.generateId || this.generateId,
                                insertionPoint: this.options.insertionPoint,
                                Renderer: this.options.Renderer,
                                index: n
                            }));
                            return this.plugins.onProcessSheet(s), s
                        }, t.removeStyleSheet = function(e) {
                            return e.detach(), Ge.remove(e), this
                        }, t.createRule = function(e, t, n) {
                            if (void 0 === t && (t = {}), void 0 === n && (n = {}), "object" == typeof e) return this.createRule(void 0, e, t);
                            var s = G({}, n, {
                                name: e,
                                jss: this,
                                Renderer: this.options.Renderer
                            });
                            s.generateId || (s.generateId = this.generateId), s.classes || (s.classes = {}), s.keyframes || (s.keyframes = {});
                            var i = oe(e, t, s);
                            return i && this.plugins.onProcessRule(i), i
                        }, t.use = function() {
                            for (var e = this, t = arguments.length, n = new Array(t), s = 0; s < t; s++) n[s] = arguments[s];
                            return n.forEach((function(t) {
                                e.plugins.use(t)
                            })), this
                        }, e
                    }();
                "object" == typeof CSS && null != CSS && CSS;
                const mt = new ut(ot);
                var pt = "@global",
                    gt = "@global ",
                    ft = function() {
                        function e(e, t, n) {
                            for (var s in this.type = "global", this.at = pt, this.isProcessed = !1, this.key = e, this.options = n, this.rules = new je(G({}, n, {
                                    parent: this
                                })), t) this.rules.add(s, t[s]);
                            this.rules.process()
                        }
                        var t = e.prototype;
                        return t.getRule = function(e) {
                            return this.rules.get(e)
                        }, t.addRule = function(e, t, n) {
                            var s = this.rules.add(e, t, n);
                            return s && this.options.jss.plugins.onProcessRule(s), s
                        }, t.replaceRule = function(e, t, n) {
                            var s = this.rules.replace(e, t, n);
                            return s && this.options.jss.plugins.onProcessRule(s), s
                        }, t.indexOf = function(e) {
                            return this.rules.indexOf(e)
                        }, t.toString = function(e) {
                            return this.rules.toString(e)
                        }, e
                    }(),
                    yt = function() {
                        function e(e, t, n) {
                            this.type = "global", this.at = pt, this.isProcessed = !1, this.key = e, this.options = n;
                            var s = e.substr(8);
                            this.rule = n.jss.createRule(s, t, G({}, n, {
                                parent: this
                            }))
                        }
                        return e.prototype.toString = function(e) {
                            return this.rule ? this.rule.toString(e) : ""
                        }, e
                    }(),
                    vt = /\s*,\s*/g;

                function bt(e, t) {
                    for (var n = e.split(vt), s = "", i = 0; i < n.length; i++) s += t + " " + n[i].trim(), n[i + 1] && (s += ", ");
                    return s
                }
                const St = function() {
                    return {
                        onCreateRule: function(e, t, n) {
                            if (!e) return null;
                            if (e === pt) return new ft(e, t, n);
                            if ("@" === e[0] && e.substr(0, 8) === gt) return new yt(e, t, n);
                            var s = n.parent;
                            return s && ("global" === s.type || s.options.parent && "global" === s.options.parent.type) && (n.scoped = !1), n.selector || !1 !== n.scoped || (n.selector = e), null
                        },
                        onProcessRule: function(e, t) {
                            "style" === e.type && t && (function(e, t) {
                                var n = e.options,
                                    s = e.style,
                                    i = s ? s[pt] : null;
                                if (i) {
                                    for (var r in i) t.addRule(r, i[r], G({}, n, {
                                        selector: bt(r, e.selector)
                                    }));
                                    delete s[pt]
                                }
                            }(e, t), function(e, t) {
                                var n = e.options,
                                    s = e.style;
                                for (var i in s)
                                    if ("@" === i[0] && i.substr(0, 7) === pt) {
                                        var r = bt(i.substr(7), e.selector);
                                        t.addRule(r, s[i], G({}, n, {
                                            selector: r
                                        })), delete s[i]
                                    }
                            }(e, t))
                        }
                    }
                };
                var Ct = /[A-Z]/g,
                    wt = /^ms-/,
                    Et = {};

                function Tt(e) {
                    return "-" + e.toLowerCase()
                }
                const Mt = function(e) {
                    if (Et.hasOwnProperty(e)) return Et[e];
                    var t = e.replace(Ct, Tt);
                    return Et[e] = wt.test(t) ? "-" + t : t
                };

                function xt(e) {
                    var t = {};
                    for (var n in e) {
                        t[0 === n.indexOf("--") ? n : Mt(n)] = e[n]
                    }
                    return e.fallbacks && (Array.isArray(e.fallbacks) ? t.fallbacks = e.fallbacks.map(xt) : t.fallbacks = xt(e.fallbacks)), t
                }
                const kt = function() {
                    return {
                        onProcessStyle: function(e) {
                            if (Array.isArray(e)) {
                                for (var t = 0; t < e.length; t++) e[t] = xt(e[t]);
                                return e
                            }
                            return xt(e)
                        },
                        onChangeValue: function(e, t, n) {
                            if (0 === t.indexOf("--")) return e;
                            var s = Mt(t);
                            return t === s ? e : (n.prop(s, e), null)
                        }
                    }
                };
                class Rt {
                    constructor(e) {
                        this.defaultLightModePalette = {
                            "--color0": "#e2e0dd80",
                            "--color1": "#FFFFFF",
                            "--color2": "#000000",
                            "--color3": "#0585fe",
                            "--color4": "#35b350",
                            "--color5": "#ffab00",
                            "--color6": "#e1e2dd",
                            "--color7": "#c3c4bf"
                        }, this.defaultDarkModePalette = {
                            "--color0": "#1d1f22e0",
                            "--color1": "#000000",
                            "--color2": "#FFFFFF",
                            "--color3": "#0585fe",
                            "--color4": "#35b350",
                            "--color5": "#ffab00",
                            "--color6": "#1e1d22",
                            "--color7": "#3c3b40"
                        }, this.defaultStyles = {
                            ":root": {
                                "--color0": "#1d1f22e0",
                                "--color1": "#000000",
                                "--color2": "#FFFFFF",
                                "--color3": "#0585fe",
                                "--color4": "#35b350",
                                "--color5": "#ffab00",
                                "--color6": "#1e1d22",
                                "--color7": "#3c3b40",
                                "--color8": "#41008c",
                                "--color9": "#3e0070",
                                "--color10": "#2e0052",
                                "--color11": "rgba(65,0,139,1)"
                            },
                            ".noselect": {
                                userSelect: "none"
                            },
                            "#playerUI": {
                                width: "100%",
                                height: "100%",
                                position: "relative"
                            },
                            "#videoElementParent": {
                                width: "100%",
                                height: "100%",
                                position: "absolute",
                                backgroundColor: "var(--color1)"
                            },
                            "#uiFeatures": {
                                width: "100%",
                                height: "100%",
                                zIndex: "30",
                                position: "relative",
                                color: "var(--color2)",
                                pointerEvents: "none",
                                overflow: "hidden"
                            },
                            ".UiTool .tooltiptext": {
                                visibility: "hidden",
                                width: "auto",
                                color: "var(--color2)",
                                textAlign: "center",
                                borderRadius: "15px",
                                padding: "0px 10px",
                                fontFamily: "'Montserrat', sans-serif",
                                fontSize: "0.75rem",
                                letterSpacing: "0.75px",
                                position: "absolute",
                                top: "0",
                                transform: "translateY(25%)",
                                left: "125%",
                                zIndex: "20"
                            },
                            ".UiTool:hover .tooltiptext": {
                                visibility: "visible",
                                backgroundColor: "var(--color7)"
                            },
                            "#connection .tooltiptext": {
                                top: "125%",
                                transform: "translateX(-25%)",
                                left: "0",
                                zIndex: "20",
                                padding: "5px 10px"
                            },
                            "#connection": {
                                position: "absolute",
                                bottom: "8%",
                                left: "5%",
                                fontFamily: "'Michroma', sans-serif",
                                height: "3rem",
                                width: "3rem",
                                pointerEvents: "all"
                            },
                            "#settings-panel .tooltiptext": {
                                display: "block",
                                top: "125%",
                                transform: "translateX(-50%)",
                                left: "0",
                                zIndex: "20",
                                padding: "5px 10px",
                                border: "3px solid var(--color3)",
                                width: "max-content",
                                fallbacks: [{
                                    width: "max-content"
                                }, {
                                    border: "3px solid var(--color3)"
                                }, {
                                    padding: "5px 10px"
                                }, {
                                    zIndex: "20"
                                }, {
                                    left: "0"
                                }, {
                                    transform: "translateX(-50%)"
                                }, {
                                    top: "125%"
                                }, {
                                    display: "block"
                                }]
                            },
                            "#controls": {
                                position: "absolute",
                                top: "3%",
                                left: "2%",
                                fontFamily: "'Michroma', sans-serif",
                                pointerEvents: "all",
                                display: "block"
                            },
                            "#controls>*": {
                                marginBottom: "0.5rem",
                                borderRadius: "50%",
                                display: "block",
                                height: "2rem",
                                lineHeight: "1.75rem",
                                padding: "0.5rem"
                            },
                            "#controls #additionalinfo": {
                                textAlign: "center",
                                fontFamily: "'Montserrat', sans-serif"
                            },
                            "#fullscreen-btn": {
                                padding: "0.6rem !important"
                            },
                            "#minimizeIcon": {
                                display: "none"
                            },
                            "#settingsBtn, #statsBtn": {
                                cursor: "pointer"
                            },
                            "#uiFeatures button": {
                                backgroundColor: "var(--color7)",
                                border: "1px solid var(--color7)",
                                color: "var(--color2)",
                                position: "relative",
                                width: "3rem",
                                height: "3rem",
                                padding: "0.5rem",
                                textAlign: "center"
                            },
                            "#uiFeatures button:hover": {
                                backgroundColor: "var(--color3)",
                                border: "3px solid var(--color3)",
                                transition: "0.25s ease",
                                paddingLeft: "0.55rem",
                                paddingTop: "0.55rem"
                            },
                            "#uiFeatures button:active": {
                                border: "3px solid var(--color3)",
                                backgroundColor: "var(--color7)",
                                paddingLeft: "0.55rem",
                                paddingTop: "0.55rem"
                            },
                            ".btn-flat": {
                                backgroundColor: "transparent",
                                color: "var(--color2)",
                                fontFamily: "'Montserrat'",
                                fontWeight: "bold",
                                border: "3px solid var(--color3)",
                                borderRadius: "1rem",
                                fontSize: "0.75rem",
                                paddingLeft: "0.5rem",
                                paddingRight: "0.5rem",
                                cursor: "pointer",
                                textAlign: "center"
                            },
                            ".btn-flat:hover": {
                                backgroundColor: "var(--color3)",
                                transition: "ease 0.3s"
                            },
                            ".btn-flat:disabled": {
                                background: "var(--color7)",
                                borderColor: "var(--color3)",
                                color: "var(--color3)",
                                cursor: "default"
                            },
                            ".btn-flat:active": {
                                backgroundColor: "transparent"
                            },
                            ".btn-flat:focus": {
                                outline: "none"
                            },
                            "#uiFeatures img": {
                                width: "100%",
                                height: "100%"
                            },
                            ".panel-wrap": {
                                position: "absolute",
                                top: "0",
                                bottom: "0",
                                right: "0",
                                height: "100%",
                                minWidth: "20vw",
                                maxWidth: "90vw",
                                transform: "translateX(100%)",
                                transition: ".3s ease-out",
                                pointerEvents: "all",
                                overflowY: "auto",
                                overflowX: "hidden",
                                backgroundColor: "var(--color0)"
                            },
                            ".panel-wrap-visible": {
                                transform: "translateX(0%)"
                            },
                            ".panel": {
                                overflowY: "auto",
                                padding: "1em"
                            },
                            "#settingsHeading, #statsHeading": {
                                display: "inline-block",
                                fontSize: "2em",
                                marginBlockStart: "0.67em",
                                marginBlockEnd: "0.67em",
                                marginInlineStart: "0px",
                                marginInlineEnd: "0px",
                                position: "relative",
                                padding: "0 0 0 2rem"
                            },
                            "#settingsClose, #statsClose": {
                                margin: "0.5rem",
                                paddingTop: "0.5rem",
                                paddingBottom: "0.5rem",
                                paddingRight: "0.5rem",
                                fontSize: "2em",
                                float: "right"
                            },
                            "#settingsClose:after, #statsClose:after": {
                                paddingLeft: "0.5rem",
                                display: "inline-block",
                                content: '"\\00d7"'
                            },
                            "#settingsClose:hover, #statsClose:hover": {
                                color: "var(--color3)",
                                transition: "ease 0.3s"
                            },
                            "#settingsContent, #statsContent": {
                                marginLeft: "2rem",
                                marginRight: "2rem"
                            },
                            ".setting": {
                                display: "flex",
                                flexDirection: "row",
                                justifyContent: "space-between",
                                padding: "0.15rem 10px 0.15rem 10px"
                            },
                            ".settings-text": {
                                color: "var(--color2)",
                                verticalAlign: "middle",
                                fontWeight: "normal"
                            },
                            ".settings-option": {
                                width: "100%",
                                textOverflow: "ellipsis",
                                whiteSpace: "nowrap"
                            },
                            "#connectOverlay, #playOverlay, #infoOverlay, #errorOverlay, #afkOverlay, #disconnectOverlay": {
                                zIndex: "30",
                                position: "absolute",
                                color: "var(--color2)",
                                fontSize: "1.8em",
                                width: "100%",
                                height: "100%",
                                backgroundColor: "var(--color1)",
                                alignItems: "center",
                                justifyContent: "center",
                                textTransform: "uppercase"
                            },
                            ".clickableState": {
                                alignItems: "center",
                                justifyContent: "center",
                                display: "flex",
                                cursor: "pointer"
                            },
                            ".textDisplayState": {
                                display: "flex"
                            },
                            ".hiddenState": {
                                display: "none"
                            },
                            "#playButton, #connectButton": {
                                display: "inline-block",
                                height: "auto",
                                zIndex: "30"
                            },
                            "img#playButton": {
                                maxWidth: "241px",
                                width: "10%"
                            },
                            "#uiInteraction": {
                                position: "fixed"
                            },
                            "#UIInteractionButtonBoundary": {
                                padding: "2px"
                            },
                            "#UIInteractionButton": {
                                cursor: "pointer"
                            },
                            ".btn-overlay": {
                                verticalAlign: "middle",
                                display: "inline-block"
                            },
                            ".tgl-switch": {
                                verticalAlign: "middle",
                                display: "inline-block"
                            },
                            ".tgl-switch .tgl": {
                                display: "none"
                            },
                            ".tgl, .tgl:after, .tgl:before, .tgl *, .tgl *:after, .tgl *:before, .tgl+.tgl-slider": {
                                "-webkit-box-sizing": "border-box",
                                boxSizing: "border-box"
                            },
                            ".tgl::-moz-selection, .tgl:after::-moz-selection, .tgl:before::-moz-selection, .tgl *::-moz-selection, .tgl *:after::-moz-selection, .tgl *:before::-moz-selection, .tgl+.tgl-slider::-moz-selection": {
                                background: "none"
                            },
                            ".tgl::selection, .tgl:after::selection, .tgl:before::selection, .tgl *::selection, .tgl *:after::selection, .tgl *:before::selection, .tgl+.tgl-slider::selection": {
                                background: "none"
                            },
                            ".tgl-slider": {},
                            ".tgl+.tgl-slider": {
                                outline: "0",
                                display: "block",
                                width: "40px",
                                height: "18px",
                                position: "relative",
                                cursor: "pointer",
                                userSelect: "none"
                            },
                            ".tgl+.tgl-slider:after, .tgl+.tgl-slider:before": {
                                position: "relative",
                                display: "block",
                                content: '""',
                                width: "50%",
                                height: "100%"
                            },
                            ".tgl+.tgl-slider:after": {
                                left: "0"
                            },
                            ".tgl+.tgl-slider:before": {
                                display: "none"
                            },
                            ".tgl-flat+.tgl-slider": {
                                padding: "2px",
                                "-webkit-transition": "all .2s ease",
                                transition: "all .2s ease",
                                background: "var(--color6)",
                                border: "3px solid var(--color7)",
                                borderRadius: "2em"
                            },
                            ".tgl-flat+.tgl-slider:after": {
                                "-webkit-transition": "all .2s ease",
                                transition: "all .2s ease",
                                background: "var(--color7)",
                                content: '""',
                                borderRadius: "1em"
                            },
                            ".tgl-flat:checked+.tgl-slider": {
                                border: "3px solid var(--color3)"
                            },
                            ".tgl-flat:checked+.tgl-slider:after": {
                                left: "50%",
                                background: "var(--color3)"
                            },
                            ".btn-apply": {
                                display: "block !important",
                                marginLeft: "auto",
                                marginRight: "auto",
                                width: "40%"
                            },
                            ".form-control": {
                                backgroundColor: "var(--color7)",
                                border: "2px solid var(--color7)",
                                borderRadius: "4px",
                                color: "var(--color2)",
                                textAlign: "right",
                                fontFamily: "inherit"
                            },
                            ".form-control:hover": {
                                borderColor: "var(--color7)"
                            },
                            ".form-group": {
                                paddingTop: "4px",
                                display: "grid",
                                gridTemplateColumns: "80% 20%",
                                rowGap: "4px",
                                paddingRight: "10px",
                                paddingLeft: "10px"
                            },
                            ".form-group label": {
                                verticalAlign: "middle",
                                fontWeight: "normal"
                            },
                            ".settingsContainer": {
                                display: "flex",
                                flexDirection: "column",
                                borderBottom: "1px solid var(--color7)",
                                paddingTop: "10px",
                                paddingBottom: "10px"
                            },
                            ".settingsContainer> :first-child": {
                                marginTop: "4px",
                                marginBottom: "4px",
                                fontWeight: "bold",
                                justifyContent: "space-between",
                                display: "flex",
                                flexDirection: "row",
                                alignItems: "baseline"
                            },
                            ".collapse": {
                                paddingLeft: "5%"
                            },
                            "#streamTools": {
                                borderBottomRightRadius: "5px",
                                borderBottomLeftRadius: "5px",
                                userSelect: "none",
                                position: "absolute",
                                top: "0",
                                right: "2%",
                                zIndex: "100",
                                border: "4px solid var(--colour8)",
                                borderTopWidth: "0px"
                            },
                            ".settingsHeader": {
                                fontStyle: "italic"
                            },
                            "#streamToolsHeader": {
                                display: "flex",
                                flexDirection: "row",
                                justifyContent: "space-between",
                                borderBottom: "1px solid var(--colour8)",
                                backgroundColor: "var(--color7)"
                            },
                            ".streamTools": {
                                backgroundColor: "var(--color2)",
                                fontFamily: "var(--buttonFont)",
                                fontWeight: "lighter",
                                color: "var(--color7)"
                            },
                            ".streamTools-shown>#streamToolsSettings, .streamTools-shown>#streamToolsStats": {
                                display: "block"
                            },
                            "#streamToolsToggle": {
                                width: "100%"
                            },
                            "#qualityStatus": {
                                fontSize: "37px",
                                paddingRight: "4px"
                            },
                            ".svgIcon": {
                                fill: "var(--color2)"
                            },
                            ".modal": {
                                minWidth: "100vw",
                                minHeight: "100vh",
                                left: "0",
                                top: "0",
                                position: "fixed",
                                display: "flex",
                                flexDirection: "column",
                                justifyContent: "center",
                                alignItems: "center",
                                color: "var(--color2)"
                            },
                            ".innerModal": {
                                position: "relative",
                                width: "500px",
                                height: "300px",
                                backgroundColor: "var(--color0)",
                                display: "flex",
                                flexDirection: "column",
                                justifyContent: "space-between",
                                alignItems: "center",
                                borderRadius: "0.75em"
                            },
                            ".modalBtnContainer": {
                                display: "flex",
                                flexDirection: "row",
                                justifyContent: "space-around",
                                width: "100%",
                                paddingTop: "1em",
                                paddingBottom: "1em"
                            },
                            ".modalTextArea": {
                                textAlign: "left",
                                width: "95%",
                                height: "100%",
                                resize: "none",
                                fontSize: "1rem",
                                border: "1px solid var(--color2)"
                            },
                            ".modalTextArea:focus-visible": {
                                outline: "none !important",
                                border: "1px solid var(--color3)"
                            },
                            ".modal .btn-flat": {
                                fontSize: "1.0rem"
                            }
                        };
                        const {
                            customStyles: t,
                            lightModePalette: n,
                            darkModePalette: s,
                            jssInsertionPoint: i
                        } = null != e ? e : {}, r = {
                            plugins: [St(), kt()],
                            insertionPoint: i
                        };
                        mt.setup(r), this.customStyles = t, this.lightModePalette = null != n ? n : this.defaultLightModePalette, this.darkModePalette = null != s ? s : this.defaultDarkModePalette
                    }
                    applyStyleSheet() {
                        mt.createStyleSheet({
                            "@global": Object.assign(Object.assign({}, this.defaultStyles), this.customStyles)
                        }).attach()
                    }
                    applyPalette(e) {
                        const t = document.querySelector(":root");
                        t.style.setProperty("--color0", e["--color0"]), t.style.setProperty("--color1", e["--color1"]), t.style.setProperty("--color2", e["--color2"]), t.style.setProperty("--color3", e["--color3"]), t.style.setProperty("--color4", e["--color4"]), t.style.setProperty("--color5", e["--color5"]), t.style.setProperty("--color6", e["--color6"]), t.style.setProperty("--color7", e["--color7"])
                    }
                    setColorMode(e) {
                        e ? this.applyPalette(this.lightModePalette) : this.applyPalette(this.darkModePalette)
                    }
                }
            },
            753: e => {
                e.exports = function() {
                    throw new Error("ws does not work in the browser. Browser clients must use the native WebSocket object")
                }
            },
            879: (e, t, n) => {
                var s;
                n.d(t, {
                        $b: () => s,
                        Vy: () => o,
                        hW: () => r
                    }),
                    function(e) {
                        e[e.Disabled = 0] = "Disabled", e[e.Error = 1] = "Error", e[e.Warning = 2] = "Warning", e[e.Info = 3] = "Info", e[e.Debug = 4] = "Debug"
                    }(s || (s = {}));
                class i {
                    constructor() {
                        this.logLevel = s.Debug, this.includeStack = !0
                    }
                }

                function r(e) {
                    o = e
                }
                let o = new class {
                    InitLogging(e, t) {
                        this.ValidateContext(), this.context.logLevel = e, this.context.includeStack = t
                    }
                    Debug(e) {
                        this.ValidateContext(), this.context.logLevel >= s.Debug && this.CommonLog("Debug", e)
                    }
                    Info(e) {
                        this.ValidateContext(), this.context.logLevel >= s.Info && this.CommonLog("Info", e)
                    }
                    Warning(e) {
                        this.ValidateContext(), this.context.logLevel >= s.Warning && this.CommonLog("Warning", e)
                    }
                    Error(e) {
                        this.ValidateContext(), this.context.logLevel >= s.Error && this.CommonLog("Error", e)
                    }
                    CommonLog(e, t) {
                        let n = `[${e}] - ${t}`;
                        this.context.includeStack && (n += `\nStack: ${this.GetStackTrace()}`), "Error" === e ? console.error(n) : "Warning" === e ? console.warn(n) : console.log(n)
                    }
                    GetStackTrace() {
                        const e = new Error;
                        let t = "No Stack Available for this browser";
                        return e.stack && (t = e.stack.toString().replace(/Error/g, "")), t
                    }
                    ValidateContext() {
                        this.context || ("undefined" != typeof window && window ? window.loggerContext ? this.context = window.loggerContext : (this.context = new i, window.loggerContext = this.context) : this.context = new i)
                    }
                }
            },
            945: (e, t, n) => {
                function s(e) {
                    return JSON.parse(JSON.stringify({
                        buttons: e.buttons.map((e => JSON.parse(JSON.stringify({
                            pressed: e.pressed,
                            touched: e.touched,
                            value: e.value
                        })))),
                        axes: e.axes
                    }))
                }
                n.d(t, {
                    L: () => s
                })
            },
            949: function(e, t, n) {
                var s = this && this.__createBinding || (Object.create ? function(e, t, n, s) {
                        void 0 === s && (s = n);
                        var i = Object.getOwnPropertyDescriptor(t, n);
                        i && !("get" in i ? !t.__esModule : i.writable || i.configurable) || (i = {
                            enumerable: !0,
                            get: function() {
                                return t[n]
                            }
                        }), Object.defineProperty(e, s, i)
                    } : function(e, t, n, s) {
                        void 0 === s && (s = n), e[s] = t[n]
                    }),
                    i = this && this.__exportStar || function(e, t) {
                        for (var n in e) "default" === n || Object.prototype.hasOwnProperty.call(t, n) || s(t, e, n)
                    };
                Object.defineProperty(t, "__esModule", {
                    value: !0
                }), i(n(202), t), i(n(709), t);
                const r = n(202),
                    o = n(709),
                    a = new o.PixelStreamingApplicationStyle;
                a.applyStyleSheet(), document.body.onload = function() {
                    r.Logger.InitLogging(r.LogLevel.Warning, !0);
                    const e = new r.Config({
                            useUrlParams: !0
                        }),
                        t = new r.PixelStreaming(e),
                        n = new o.Application({
                            stream: t,
                            onColorModeChanged: e => a.setColorMode(e)
                        });
                    document.body.appendChild(n.rootElement), window.pixelStreaming = t
                }
            },
            952: (e, t, n) => {
                n.d(t, {
                    T: () => i
                });
                var s = n(107);
                class i extends s.E {
                    constructor(e, t, n, s, i, r = () => {}) {
                        if (super(e, t, n, s, r), i && this.hasURLParam(this.id)) {
                            const e = this.getURLParam(this.id);
                            this.flag = "false" != e.toLowerCase()
                        } else this.flag = s;
                        this.useUrlParams = i
                    }
                    getValueAsString() {
                        return this.flag ? "true" : "false"
                    }
                    enable() {
                        this.flag = !0
                    }
                    get flag() {
                        return !!this.value
                    }
                    set flag(e) {
                        this.value = e
                    }
                }
            }
        },
        t = {};

    function n(s) {
        var i = t[s];
        if (void 0 !== i) return i.exports;
        var r = t[s] = {
            exports: {}
        };
        return e[s].call(r.exports, r, r.exports, n), r.exports
    }
    return n.n = e => {
        var t = e && e.__esModule ? () => e.default : () => e;
        return n.d(t, {
            a: t
        }), t
    }, n.d = (e, t) => {
        for (var s in t) n.o(t, s) && !n.o(e, s) && Object.defineProperty(e, s, {
            enumerable: !0,
            get: t[s]
        })
    }, n.o = (e, t) => Object.prototype.hasOwnProperty.call(e, t), n.r = e => {
        "undefined" != typeof Symbol && Symbol.toStringTag && Object.defineProperty(e, Symbol.toStringTag, {
            value: "Module"
        }), Object.defineProperty(e, "__esModule", {
            value: !0
        })
    }, n(949)
})()));