"use client"

import { useEffect, useId, useMemo, useState } from "react"
import {
  CheckIcon,
  CircleAlertIcon,
  CircleDashedIcon,
  LoaderCircle,
  MinusIcon,
} from "lucide-react"
import { cn } from "cn"

import {
  Stepper,
  StepperContent,
  StepperIndicator,
  StepperItem,
  StepperNav,
  StepperPanel,
  StepperTitle,
  StepperTrigger,
} from "@/components/reui/stepper"
import {
  BaseCollapsible,
  BaseCollapsibleContent,
} from "@/components/reui/base-collapsible"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"

export type ScanStepStatus =
  | "pending"
  | "running"
  | "completed"
  | "skipped"
  | "failed"
  | "blocked"

export interface ScanProgressStep {
  id: string
  label: string
  status: string
  details?: string
}

interface StepPhase {
  id: string
  title: string
  steps: ScanProgressStep[]
}

interface Selection {
  phase: number
  task: number
}

const statusLabels: Record<ScanStepStatus, string> = {
  pending: "Waiting",
  running: "In progress",
  completed: "Completed",
  skipped: "Skipped",
  failed: "Failed",
  blocked: "Blocked",
}

const phaseSegment =
  "bg-input pointer-events-none absolute end-3 w-[1.2px] translate-x-1/2 rounded-full rtl:-translate-x-1/2"

const taskSegment =
  "bg-input pointer-events-none absolute end-2.25 w-px translate-x-1/2 rounded-full rtl:-translate-x-1/2"

const stepTitle = "data-[state=inactive]:text-muted-foreground text-pretty"

function humanize(value: string) {
  return value
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase())
}

function statusLabel(status: string) {
  return statusLabels[status as ScanStepStatus] ?? humanize(status)
}

function isResolved(status: string) {
  return (
    status === "completed" ||
    status === "skipped" ||
    status === "failed" ||
    status === "blocked"
  )
}

function phaseForStep(stepId: string) {
  if (
    stepId.includes("consent") ||
    stepId.includes("target") ||
    stepId.includes("sandbox") ||
    stepId.includes("validate")
  ) {
    return { id: "preparation", title: "Preparation", order: 0 }
  }

  if (
    stepId === "report" ||
    stepId.includes("report") ||
    stepId.includes("summary")
  ) {
    return { id: "report", title: "Report", order: 2 }
  }

  return { id: "checks", title: "Analysis checks", order: 1 }
}

function groupSteps(steps: ScanProgressStep[]): StepPhase[] {
  const groups = new Map<string, StepPhase & { order: number }>()

  for (const step of steps) {
    const phase = phaseForStep(step.id)
    const existing = groups.get(phase.id)
    if (existing) {
      existing.steps.push(step)
    } else {
      groups.set(phase.id, {
        id: phase.id,
        title: phase.title,
        order: phase.order,
        steps: [step],
      })
    }
  }

  return [...groups.values()]
    .sort((a, b) => a.order - b.order)
    .map(({ id, title, steps: phaseSteps }) => ({
      id,
      title,
      steps: phaseSteps,
    }))
}

function stepIndexFor(steps: ScanProgressStep[]) {
  const running = steps.findIndex((step) => step.status === "running")
  if (running >= 0) return running + 1

  const pending = steps.findIndex((step) => !isResolved(step.status))
  if (pending >= 0) return pending + 1

  const failed = steps.findIndex(
    (step) => step.status === "failed" || step.status === "blocked"
  )
  if (failed >= 0) return failed + 1

  return Math.max(steps.length, 1)
}

function currentSelection(phases: StepPhase[]): Selection {
  const runningPhase = phases.findIndex((phase) =>
    phase.steps.some((step) => step.status === "running")
  )
  if (runningPhase >= 0) {
    return {
      phase: runningPhase + 1,
      task: stepIndexFor(phases[runningPhase].steps),
    }
  }

  const pendingPhase = phases.findIndex((phase) =>
    phase.steps.some((step) => !isResolved(step.status))
  )
  if (pendingPhase >= 0) {
    return {
      phase: pendingPhase + 1,
      task: stepIndexFor(phases[pendingPhase].steps),
    }
  }

  const failedPhase = phases.findIndex((phase) =>
    phase.steps.some(
      (step) => step.status === "failed" || step.status === "blocked"
    )
  )
  if (failedPhase >= 0) {
    return {
      phase: failedPhase + 1,
      task: stepIndexFor(phases[failedPhase].steps),
    }
  }

  const lastPhase = phases.length
  return {
    phase: lastPhase,
    task: stepIndexFor(phases[lastPhase - 1]?.steps ?? []),
  }
}

function phaseStatus(phase: StepPhase): string {
  const statuses = phase.steps.map((step) => step.status)
  if (statuses.includes("running")) return "running"
  if (statuses.some((status) => !isResolved(status))) return "pending"
  if (statuses.includes("failed")) return "failed"
  if (statuses.includes("blocked")) return "blocked"
  if (statuses.includes("skipped")) return "skipped"
  return "completed"
}

function StatusIcon({ status }: { status: string }) {
  if (status === "completed") {
    return <CheckIcon className="size-2.5" aria-hidden="true" />
  }
  if (status === "running") {
    return <LoaderCircle className="size-2.5 animate-spin" aria-hidden="true" />
  }
  if (status === "failed" || status === "blocked") {
    return <CircleAlertIcon className="size-2.5" aria-hidden="true" />
  }
  if (status === "skipped") {
    return <MinusIcon className="size-2.5" aria-hidden="true" />
  }
  return <CircleDashedIcon className="size-2.5" aria-hidden="true" />
}

function statusIndicatorClass(status: string) {
  if (status === "failed" || status === "blocked") {
    return "data-[state=completed]:border-destructive/40 data-[state=completed]:bg-destructive/10 data-[state=completed]:text-destructive"
  }
  if (status === "skipped") {
    return "data-[state=completed]:border-muted-foreground/30 data-[state=completed]:bg-muted data-[state=completed]:text-muted-foreground"
  }
  return ""
}

export function Pattern({
  steps,
  testId = "scan-progress-stepper",
}: {
  steps: ScanProgressStep[]
  testId?: string
}) {
  const id = useId()
  const phases = useMemo(() => groupSteps(steps), [steps])
  const stepSignature = steps
    .map((step) => `${step.id}:${step.status}:${step.details ?? ""}`)
    .join("|")
  const [selection, setSelection] = useState<Selection>(() =>
    currentSelection(phases)
  )
  const flatSteps = useMemo(
    () =>
      phases.flatMap((phase, phaseIndex) =>
        phase.steps.map((step, taskIndex) => ({
          phase: phaseIndex + 1,
          task: taskIndex + 1,
          step,
        }))
      ),
    [phases]
  )

  useEffect(() => {
    setSelection(currentSelection(phases))
  }, [stepSignature])

  if (!phases.length) {
    return (
      <div
        className="rounded-lg border border-border bg-muted/20 px-4 py-3 text-sm text-muted-foreground"
        data-testid={testId}
        role="status"
      >
        Waiting for the scan service to publish its execution plan.
      </div>
    )
  }

  const selectedPhaseIndex = Math.min(
    Math.max(selection.phase - 1, 0),
    phases.length - 1
  )
  const selectedPhase = phases[selectedPhaseIndex]
  const selectedTaskIndex = Math.min(
    Math.max(selection.task - 1, 0),
    selectedPhase.steps.length - 1
  )
  const selectedPosition = flatSteps.findIndex(
    (item) =>
      item.phase === selectedPhaseIndex + 1 &&
      item.task === selectedTaskIndex + 1
  )

  function selectPhase(nextPhase: number) {
    const phase = phases[nextPhase - 1]
    if (!phase) return
    setSelection({
      phase: nextPhase,
      task: stepIndexFor(phase.steps),
    })
  }

  function moveTo(position: number) {
    const next = flatSteps[position]
    if (next) setSelection({ phase: next.phase, task: next.task })
  }

  return (
    <Stepper
      value={selectedPhaseIndex + 1}
      onValueChange={selectPhase}
      orientation="vertical"
      className="@container mx-auto max-w-lg"
      aria-label="Analysis plan phases"
      data-testid={testId}
    >
      <div className="mx-auto flex max-w-60 flex-col gap-6 @md:max-w-none @md:flex-row @md:items-start">
        <StepperNav className="flex @md:w-60 @md:shrink-0">
          {phases.map((phase, phaseIndex) => {
            const phaseNumber = phaseIndex + 1
            const active = phaseNumber === selectedPhaseIndex + 1
            const status = phaseStatus(phase)
            const completed = isResolved(status)
            const panelId = `${id}-phase-panel-${phaseNumber}`

            return (
              <StepperItem
                key={phase.id}
                step={phaseNumber}
                completed={completed}
                loading={status === "running"}
                className="relative min-h-15.25 items-end justify-start last:min-h-0"
              >
                <span
                  aria-hidden="true"
                  className={cn(
                    phaseSegment,
                    "top-0",
                    active ? "h-1.25" : "h-1.5"
                  )}
                />
                <span
                  aria-hidden="true"
                  className={cn(
                    phaseSegment,
                    "bottom-0",
                    active ? "top-7.75" : "top-7.5"
                  )}
                />
                <StepperTrigger
                  type="button"
                  id={`${id}-phase-tab-${phaseNumber}`}
                  aria-controls={panelId}
                  aria-label={`${phase.title}, ${statusLabel(status)}`}
                  className="min-h-11 gap-2 text-end aria-selected:bg-muted/50"
                >
                  <span className="flex min-w-0 flex-col">
                    <StepperTitle className={cn(stepTitle, "leading-5")}>
                      {phase.title}
                    </StepperTitle>
                    <span className="text-muted-foreground text-xs">
                      Step {phaseNumber}
                    </span>
                  </span>
                  <StepperIndicator
                    className={cn(
                      "size-5 border border-input",
                      statusIndicatorClass(status)
                    )}
                  >
                    <StatusIcon status={status} />
                  </StepperIndicator>
                </StepperTrigger>

                <BaseCollapsible open={active}>
                  <BaseCollapsibleContent className="h-(--collapsible-panel-height) overflow-hidden transition-[height] duration-200 ease-out data-ending-style:h-0 data-starting-style:h-0 motion-reduce:transition-none">
                    <Stepper
                      value={
                        active
                          ? selectedTaskIndex + 1
                          : stepIndexFor(phase.steps)
                      }
                      onValueChange={
                        active
                          ? (task) =>
                              setSelection({ phase: phaseNumber, task })
                          : undefined
                      }
                      orientation="vertical"
                      aria-label={`${phase.title} steps`}
                    >
                      <StepperNav className="ms-1 me-7.5 mt-2 mb-2.5">
                        {phase.steps.map((step, taskIndex) => {
                          const taskNumber = taskIndex + 1
                          const resolved = isResolved(step.status)
                          return (
                            <StepperItem
                              key={`${step.id}-${taskIndex}`}
                              step={taskNumber}
                              completed={resolved}
                              loading={step.status === "running"}
                              className="relative items-end"
                            >
                              {taskIndex > 0 && (
                                <span
                                  aria-hidden="true"
                                  className={cn(taskSegment, "top-0 h-1.5")}
                                />
                              )}
                              {taskNumber < phase.steps.length && (
                                <span
                                  aria-hidden="true"
                                  className={cn(taskSegment, "top-6 bottom-0")}
                                />
                              )}
                              <StepperTrigger
                                type="button"
                                id={`${id}-task-tab-${phaseNumber}-${taskNumber}`}
                                aria-controls={panelId}
                                aria-label={`${step.label}, ${statusLabel(step.status)}`}
                                className="min-h-11 gap-1.5 text-end aria-selected:bg-muted/50"
                              >
                                <StepperTitle
                                  className={cn(stepTitle, "font-normal")}
                                >
                                  {step.label}
                                </StepperTitle>
                                <StepperIndicator
                                  className={cn(
                                    "size-4.5 border border-input",
                                    statusIndicatorClass(step.status)
                                  )}
                                >
                                  <StatusIcon status={step.status} />
                                </StepperIndicator>
                              </StepperTrigger>
                            </StepperItem>
                          )
                        })}
                      </StepperNav>
                    </Stepper>
                  </BaseCollapsibleContent>
                </BaseCollapsible>
              </StepperItem>
            )
          })}
        </StepperNav>

        <Separator aria-hidden="true" className="@md:hidden" />
        <Separator
          aria-hidden="true"
          orientation="vertical"
          className="hidden @md:block"
        />

        <div className="flex min-w-0 flex-1 flex-col gap-3 pe-8 text-end @md:pe-0 @md:text-start">
          <StepperPanel>
            {phases.map((phase, phaseIndex) => {
              const phaseNumber = phaseIndex + 1
              const activeTaskNumber =
                phaseNumber === selectedPhaseIndex + 1
                  ? selectedTaskIndex + 1
                  : stepIndexFor(phase.steps)
              const step = phase.steps[activeTaskNumber - 1]
              const panelId = `${id}-phase-panel-${phaseNumber}`
              if (!step) return null

              return (
                <StepperContent key={phase.id} value={phaseNumber}>
                  <div id={panelId} className="min-w-0">
                    <p className="text-muted-foreground text-xs">
                      Step {activeTaskNumber} of {phase.steps.length} ·{" "}
                      {statusLabel(step.status)}
                    </p>
                    <p className="text-sm font-medium">{step.label}</p>
                    {step.details && (
                      <p className="text-muted-foreground text-sm leading-5">
                        {step.details}
                      </p>
                    )}
                  </div>
                </StepperContent>
              )
            })}
          </StepperPanel>
          <div className="flex justify-end gap-2 @md:justify-start">
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="min-h-11"
              disabled={selectedPosition <= 0}
              onClick={() => moveTo(selectedPosition - 1)}
              aria-label="Previous analysis step"
            >
              Previous
            </Button>
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="min-h-11"
              disabled={selectedPosition >= flatSteps.length - 1}
              onClick={() => moveTo(selectedPosition + 1)}
              aria-label="Next analysis step"
            >
              Next
            </Button>
          </div>
        </div>
      </div>
    </Stepper>
  )
}
