import { PoxCommand, Real, Stub, Wallet, logCommand } from "./pox_CommandModel.ts";
import { expect } from "vitest";
import { Cl } from "@stacks/transactions";

/**
 * Implements the `PoxCommand` interface to get the info returned from the
 * `stx-account`.
 */
export class GetStxAccountCommand implements PoxCommand {
  readonly wallet: Wallet;

  /**
   * Constructs a new `GetStxAccountCommand`.
   *
   * @param wallet The wallet information, including the STX address used to
   *               query the `stx-account`.
   */
  constructor(wallet: Wallet) {
    this.wallet = wallet;
  }

  check(_model: Readonly<Stub>): boolean {
    // Can always check the `stx-account` info.
    return true;
  }

  run(model: Stub, real: Real): void {
    const actual = model.wallets.get(this.wallet.stxAddress)!;
    expect(real.network.runSnippet(`(stx-account '${actual.stxAddress})`))
      .toBeTuple({
        "locked": Cl.uint(actual.amountLocked),
        "unlocked": Cl.uint(actual.amountUnlocked),
        "unlock-height": Cl.uint(actual.unlockHeight),
      });

    // Log to console for debugging purposes. This is not necessary for the
    // test to pass but it is useful for debugging and eyeballing the test.
    logCommand(`✓ ${this.wallet.label}`, "stx-account", "lock-amount", actual.amountLocked.toString(), "unlocked-amount", actual.amountUnlocked.toString(), "unlocked-height", actual.unlockHeight.toString());
  }

  toString() {
    // fast-check will call toString() in case of errors, e.g. property failed.
    // It will then make a minimal counterexample, a process called 'shrinking'
    // https://github.com/dubzzz/fast-check/issues/2864#issuecomment-1098002642
    return `${this.wallet.label} stx-account`;
  }
}
