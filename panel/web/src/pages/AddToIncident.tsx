// SPDX-License-Identifier: AGPL-3.0-or-later

// Dodanie alertów do incydentu: nowy (tytuł, waga) albo istniejący aktywny.
import { useEffect, useState } from "react";
import { Button, Modal, SegmentedControl, Select, Stack, TextInput, Textarea } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { incidentsApi, incidentSeverityColors, type Incident, type IncidentSeverity } from "../api";

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
  const { t } = useTranslation("incidents");
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
      notifications.show({ color: "green", message: t("add.done", { count: alertIds.length, id }) });
      onClose();
      navigate(`/incidents/${id}`);
    } catch (e) {
      notifications.show({ color: "red", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal opened={opened} onClose={onClose} title={alertIds.length ? t("add.titleAlerts", { count: alertIds.length }) : t("add.titleNew")} centered>
      <Stack>
        <SegmentedControl
          value={mode}
          onChange={setMode}
          data={[
            { value: "new", label: t("add.modeNew") },
            { value: "existing", label: t("add.modeExisting", { count: active.length }), disabled: active.length === 0 },
          ]}
        />
        {mode === "new" ? (
          <>
            <TextInput label={t("add.title")} required value={title} onChange={(e) => setTitle(e.currentTarget.value)} autoFocus />
            <Select
              label={t("add.severity")}
              value={severity}
              allowDeselect={false}
              onChange={(v) => v && setSeverity(v as IncidentSeverity)}
              data={Object.keys(incidentSeverityColors).map((value) => ({ value, label: t(`severity.${value}`) }))}
            />
            <Textarea label={t("add.description")} autosize minRows={2} value={description} onChange={(e) => setDescription(e.currentTarget.value)} />
          </>
        ) : (
          <Select
            label={t("add.incident")}
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
          {mode === "new" ? t("add.create") : t("add.addTo")}
        </Button>
      </Stack>
    </Modal>
  );
}
