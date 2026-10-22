// SPDX-License-Identifier: AGPL-3.0-or-later

import { Component, type ErrorInfo, type ReactNode } from "react";
import { Alert, Button, Code, Group, Stack, Text } from "@mantine/core";

// Granica błędów strony: wyjątek w renderowaniu jednego modułu pokazuje
// komunikat w miejscu strony, a menu i reszta panelu działają dalej
// (bez niej React odmontowywał cały panel – pusta biała strona).
// Klucz z adresu strony (resetKey) czyści błąd po przejściu do innej strony.
interface Props {
  children: ReactNode;
  resetKey: string;
}

interface State {
  error: Error | null;
  key: string;
}

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null, key: this.props.resetKey };

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error };
  }

  static getDerivedStateFromProps(props: Props, state: State): Partial<State> | null {
    return props.resetKey !== state.key ? { error: null, key: props.resetKey } : null;
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("błąd strony panelu", error, info.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <Alert color="red" title="Ta strona napotkała błąd">
        <Stack gap="xs">
          <Text size="sm">
            Coś poszło nie tak przy wyświetlaniu strony. Reszta panelu działa – możesz przejść do innego modułu albo spróbować
            ponownie. Jeśli błąd się powtarza, zgłoś go z treścią poniżej.
          </Text>
          <Code block>{this.state.error.message}</Code>
          <Group>
            <Button size="xs" variant="light" onClick={() => this.setState({ error: null })}>
              Spróbuj ponownie
            </Button>
          </Group>
        </Stack>
      </Alert>
    );
  }
}
