import { Paper, Stack, Text, Title } from "@mantine/core";
import { IconHammer } from "@tabler/icons-react";

export default function ComingSoon({ name, what }: { name: string; what: string }) {
  return (
    <Paper withBorder p="xl" maw={640}>
      <Stack align="flex-start" gap="xs">
        <IconHammer size={32} color="var(--mantine-color-dimmed)" />
        <Title order={3}>{name}</Title>
        <Text c="dimmed">{what}</Text>
        <Text size="sm">Moduł powstaje w ramach etapu 2 (roadmapa, załącznik C).</Text>
      </Stack>
    </Paper>
  );
}
