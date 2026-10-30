import { LedgerEvents } from "../events";

/** A hand-driven EventSource: tests push messages and errors into it. */
class FakeEventSource {
  public onerror: ((e: unknown) => void) | null = null;
  public closed = false;
  private handlers: Record<string, Function[]> = {};

  constructor(public url: string) {}

  public addEventListener(name: string, handler: Function): void {
    (this.handlers[name] = this.handlers[name] || []).push(handler);
  }

  public emit(name: string, data: unknown): void {
    (this.handlers[name] || []).forEach((h) => h({ data: JSON.stringify(data) }));
  }

  public close(): void {
    this.closed = true;
  }
}

const setup = (url = "http://host:5261") => {
  const sources: FakeEventSource[] = [];
  const events = new LedgerEvents(url, (u: string) => {
    const source = new FakeEventSource(u);
    sources.push(source);
    return source as any;
  });
  return { events, sources };
};

describe("LedgerEvents construction", () => {
  it("rejects a URL without a protocol", () => {
    expect(() => setup("host:5261")).toThrow("Activecore URL must include http:// or https://");
  });
});

describe("LedgerEvents.subscribeToActivity", () => {
  it("subscribes to every stream and hands the callback the stream", () => {
    const { events, sources } = setup();
    const received: unknown[] = [];
    events.subscribeToActivity((s: unknown) => received.push(s));

    expect(sources[0].url).toBe("http://host:5261/api/activity/subscribe");
    sources[0].emit("message", { stream: { id: "s1" } });
    expect(received).toEqual([{ id: "s1" }]);
  });

  it("subscribes to a single stream when given an id", () => {
    const { events, sources } = setup();
    events.subscribeToActivity("abc", () => undefined);

    expect(sources[0].url).toBe("http://host:5261/api/activity/subscribe/abc");
  });

  it("throws when a stream id is given without a callback", () => {
    const { events } = setup();
    expect(() => (events as any).subscribeToActivity("abc")).toThrow("No Callback defined");
  });

  it("returns a distinct reference for each subscription", () => {
    const { events } = setup();
    const a = events.subscribeToActivity(() => undefined);
    const b = events.subscribeToActivity(() => undefined);
    expect(a).not.toBe(b);
  });
});

describe("LedgerEvents.subscribeToEvent", () => {
  it.each([
    [undefined, "events"],
    [{ contract: "tokens" }, "events/tokens"],
    [{ contract: "tokens", event: "minted" }, "events/tokens/minted"],
  ])("config %j opens %s", (config, resource) => {
    const { events, sources } = setup();
    events.subscribeToEvent(() => undefined, config as any);

    expect(sources[0].url).toBe(`http://host:5261/api/${resource}`);
  });

  it("rejects an event without a contract, and opens nothing", () => {
    const { events, sources } = setup();
    expect(() => events.subscribeToEvent(() => undefined, { event: "minted" } as any)).toThrow(
      "Must pass contract to use event"
    );
    expect(sources).toHaveLength(0);
  });

  it("hands the callback event.data", () => {
    const { events, sources } = setup();
    const received: unknown[] = [];
    events.subscribeToEvent((d: unknown) => received.push(d));

    sources[0].emit("message", { event: { data: { amount: 5 } } });
    expect(received).toEqual([{ amount: 5 }]);
  });
});

describe("LedgerEvents errors and unsubscribe", () => {
  it("re-emits a source error on errorEvents", () => {
    const { events, sources } = setup();
    const errors: unknown[] = [];
    events.errorEvents.on("ledgerEventError", (e) => errors.push(e));
    events.subscribeToActivity(() => undefined);

    const failure = new Error("stream dropped");
    sources[0].onerror!(failure);
    expect(errors).toEqual([failure]);
  });

  it("closes the source and returns true on unsubscribe", () => {
    const { events, sources } = setup();
    const id = events.subscribeToActivity(() => undefined);

    expect(events.unsubscribe(id)).toBe(true);
    expect(sources[0].closed).toBe(true);
  });

  it("returns false for an unknown or already-removed reference", () => {
    const { events } = setup();
    const id = events.subscribeToActivity(() => undefined);

    expect(events.unsubscribe(999)).toBe(false);
    expect(events.unsubscribe(id)).toBe(true);
    expect(events.unsubscribe(id)).toBe(false);
  });
});
