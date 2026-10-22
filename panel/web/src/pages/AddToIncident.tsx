// SPDX-License-Identifier: AGPL-3.0-or-later

// Dodanie alertów do incydentu: nowy (tytuł, waga) albo istniejący aktywny.
import { useEffect, useState } from "react";
import { Button, Modal, SegmentedControl, Select, Stack, TextInput, Textarea } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useNavigate } from "react-router-dom";
import { incidentsApi, incidentSeverityLabels, type Incident, type IncidentSeverity } from "../api";

export default function AddToIncident({
  alertIds,
  defaultTitle,
  opened,
  onClose,
}: {
  alertIds: number[];
  defaultTitle?: string;
  opened: boolean;
  onClose: () => void;
}) {
  const navigate = useNavigate();
  const [mode, setMode] = useState("new");
  const [active, setActive] = useState<Incident[]>([]);
  const [target, setTarget] = useState<string | null>(null);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState<IncidentSeverity>("medium");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!opened) return;
    setTitle(defaultTitle ?? "");
    setDescription("");
    incidentsApi
      .list("active")
      .then((r) => setActive(r.incidents))
      .catch(() => setActive([]));
  }, [opened, defaultTitle]);

  const submit = async () => {
    setBusy(true);
    try {
      let id: number;
      if (mode === "new") {
        id = (await incidentsApi.create({ title, description, severity, alert_ids: alertIds })).incident.id;
      } else {
        id = Number(target);
        await incidentsApi.addAlerts(id, alertIds);
      }
      notifications.show({ color: "green", message: `Alerty (${alertIds.length}) w incydencie #${id}` });
      onClose();
      navigate(`/incidents/${id}`);
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal opened={opened} onClose={onClose} title={alertIds.length ? `Alerty do incydentu (${alertIds.length})` : "Nowy incydent"} centered>
      <Stack>
        <SegmentedControl
          value={mode}
          onChange={setMode}
          data={[
            { value: "new", label: "Nowy incydent" },
            { value: "existing", label: `Istniejący (${active.length})`, disabled: active.length === 0 },
          ]}
        />
        {mode === "new" ? (
          <>
            <TextInput label="Tytuł" required value={title} onChange={(e) => setTitle(e.currentTarget.value)} autoFocus />
            <Select
              label="Waga"
              value={severity}
              allowDeselect={false}
              onChange={(v) => v && setSeverity(v as IncidentSeverity)}
              data={Object.entries(incidentSeverityLabels).map(([value, l]) => ({ value, label: l.label }))}
            />
            <Textarea label="Opis (opcjonalnie)" autosize minRows={2} value={description} onChange={(e) => setDescription(e.currentTarget.value)} />
          </>
        ) : (
          <Select
            label="Incydent"
            searchable
            value={target}
            onChange={setTarget}
            data={active.map((i) => ({ value: String(i.id), label: `#${i.id} ${i.title}` }))}
          />
        )}
        <Button
          loading={busy}
          disabled={mode === "new" ? title.trim().length < 3 : !target}
          onClick={() => void submit()}
        >
          {mode === "new" ? "Utwórz incydent" : "Dodaj do incydentu"}
        </Button>
      </Stack>
    </Modal>
  );
}
