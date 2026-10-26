<script lang="ts">
  import type { ConfirmKind } from '../lib/types';

  type Props = {
    open: boolean;
    kind: ConfirmKind;
    message: string;
    lang: 'en' | 'ru';
    oncancel: () => void;
    onconfirm: () => void;
  };

  let { open, kind, message, lang, oncancel, onconfirm }: Props = $props();
  let typed = $state('');

  $effect(() => {
    if (open) typed = '';
  });

  const ok = $derived(typed.trim().toUpperCase() === kind);
</script>

{#if open}
  <div class="modal" role="dialog" aria-modal="true">
    <div class="modal-card">
      <h2>{lang === 'ru' ? 'Подтверждение' : 'Confirm'}</h2>
      <p>{message}</p>
      <input bind:value={typed} placeholder={kind} autocomplete="off" />
      <div class="modal-actions">
        <button type="button" class="ghost" onclick={oncancel}>
          {lang === 'ru' ? 'Отмена' : 'Cancel'}
        </button>
        <button type="button" class="danger" disabled={!ok} onclick={onconfirm}>
          {lang === 'ru' ? 'Выполнить' : 'Run'}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .modal {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.55);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 40;
  }
  .modal-card {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 10px;
    padding: 1.25rem;
    width: min(420px, 92vw);
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  .modal-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
  }
  input,
  button {
    padding: 0.4rem 0.65rem;
    border-radius: 6px;
    border: 1px solid var(--line);
    background: var(--panel);
  }
  button.danger { border-color: #b91c1c; cursor: pointer; }
  button.ghost { opacity: 0.85; cursor: pointer; }
  button:disabled { opacity: 0.4; cursor: not-allowed; }
</style>
