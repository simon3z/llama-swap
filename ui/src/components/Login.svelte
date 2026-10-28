<script lang="ts">
  import { login } from "../lib/auth";
  import * as Card from "$lib/components/ui/card/index.js";
  import { Input } from "$lib/components/ui/input/index.js";
  import { Button } from "$lib/components/ui/button/index.js";
  import { KeyRound, LogIn } from "@lucide/svelte";

  let apiKey = $state("");
  let submitting = $state(false);
  let error = $state("");

  async function handleSubmit(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    if (submitting || !apiKey.trim()) return;
    submitting = true;
    error = "";
    const ok = await login(apiKey.trim());
    submitting = false;
    if (!ok) error = "That key was rejected. Check it and try again.";
  }
</script>

<div class="flex h-full min-h-screen items-center justify-center bg-background p-4">
  <Card.Root class="w-full max-w-sm">
    <Card.Header>
      <div class="mx-auto flex size-10 items-center justify-center rounded-lg bg-muted">
        <KeyRound class="size-5 text-muted-foreground" />
      </div>
      <Card.Title class="text-center">Sign in to llama-swap</Card.Title>
      <Card.Description class="text-center">
        This server requires an API key. Enter one from your llama-swap config
        (apiKeys) to unlock the UI.
      </Card.Description>
    </Card.Header>
    <Card.Content>
      <form onsubmit={handleSubmit} class="flex flex-col gap-3">
        <Input
          type="password"
          placeholder="API key"
          bind:value={apiKey}
          autofocus
          autocomplete="current-password"
          class="h-10"
        />
        {#if error}
          <p class="text-destructive text-sm" role="alert">{error}</p>
        {/if}
        <Button type="submit" disabled={submitting || !apiKey.trim()}>
          <LogIn class="size-4" />
          Sign in
        </Button>
      </form>
    </Card.Content>
  </Card.Root>
</div>
