from adam.contracts.raw_event import RawEvent

class EventNormaliser:
    @staticmethod
    def canonicalize_path(path: str) -> str:
        if not path:
            return ""
        p = path.strip().lower().replace("/", "\\")
        while "\\\\" in p:
            p = p.replace("\\\\", "\\")
        return p

    @staticmethod
    def normalise(event: RawEvent) -> RawEvent:
        attrs = event.attributes.copy()
        if "target_object" in attrs:
            attrs["target_object"] = EventNormaliser.canonicalize_path(attrs["target_object"])
        if "path" in attrs:
            attrs["path"] = EventNormaliser.canonicalize_path(attrs["path"])
            
        if event.process and event.process.image:
            event.process.image = EventNormaliser.canonicalize_path(event.process.image)
            
        event.attributes = attrs
        return event
