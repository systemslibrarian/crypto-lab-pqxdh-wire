import type { Page } from '@playwright/test'

export interface ContrastFailure {
  selector: string
  text: string
  ratio: number
  required: number
}

export async function auditContrast(
  page: Page,
  rootSelector = 'body *',
  includeAriaHidden = false,
): Promise<ContrastFailure[]> {
  return page.evaluate(
    ([within, allowAriaHidden]) => {
      type Rgba = { r: number; g: number; b: number; a: number }
      const parse = (value: string): Rgba | undefined => {
        const numbers = value.match(/[\d.]+/g)?.map(Number)
        if (!numbers || numbers.length < 3) return undefined
        return { r: numbers[0], g: numbers[1], b: numbers[2], a: numbers[3] ?? 1 }
      }
      const over = (foreground: Rgba, background: Rgba): Rgba => {
        const alpha = foreground.a + background.a * (1 - foreground.a)
        if (alpha === 0) return { r: 0, g: 0, b: 0, a: 0 }
        return {
          r: (foreground.r * foreground.a + background.r * background.a * (1 - foreground.a)) / alpha,
          g: (foreground.g * foreground.a + background.g * background.a * (1 - foreground.a)) / alpha,
          b: (foreground.b * foreground.a + background.b * background.a * (1 - foreground.a)) / alpha,
          a: alpha,
        }
      }
      const channel = (value: number): number => {
        const normalized = value / 255
        return normalized <= 0.04045
          ? normalized / 12.92
          : ((normalized + 0.055) / 1.055) ** 2.4
      }
      const luminance = (color: Rgba): number =>
        0.2126 * channel(color.r) + 0.7152 * channel(color.g) + 0.0722 * channel(color.b)
      const ratio = (left: Rgba, right: Rgba): number => {
        const lighter = Math.max(luminance(left), luminance(right))
        const darker = Math.min(luminance(left), luminance(right))
        return (lighter + 0.05) / (darker + 0.05)
      }
      const white = { r: 255, g: 255, b: 255, a: 1 }
      const describe = (element: Element): string => {
        const id = element.id ? `#${element.id}` : ''
        const classes = [...element.classList].join('.')
        return `${element.tagName.toLowerCase()}${id}${classes ? `.${classes}` : ''}`
      }
      const hiddenFromA11y = (element: Element): boolean =>
        !allowAriaHidden && Boolean(element.closest('[aria-hidden="true"]'))
      const ownText = (element: Element): string =>
        [...element.childNodes]
          .filter((node) => node.nodeType === Node.TEXT_NODE)
          .map((node) => node.textContent ?? '')
          .join('')
          .trim()
      const backdrop = (element: Element): Rgba => {
        let current: Element | null = element
        let accumulated = { r: 0, g: 0, b: 0, a: 0 }
        while (current) {
          const color = parse(getComputedStyle(current).backgroundColor)
          if (color) accumulated = over(accumulated, color)
          if (accumulated.a >= 1) break
          current = current.parentElement
        }
        return over(accumulated, white)
      }

      const failures: ContrastFailure[] = []
      for (const element of document.querySelectorAll(within)) {
        const text = ownText(element)
        if (!text || hiddenFromA11y(element)) continue
        const htmlElement = element as HTMLElement
        if (!htmlElement.checkVisibility?.()) continue
        if (element.closest(':disabled,[aria-disabled="true"]')) continue
        const rect = element.getBoundingClientRect()
        if (rect.width <= 0 || rect.height <= 0) continue
        const style = getComputedStyle(element)
        if (style.clipPath.includes('50%') || style.clip.includes('0px, 0px, 0px, 0px')) continue
        const foreground = parse(style.color)
        if (!foreground || foreground.a === 0) continue
        const background = backdrop(element)
        const paintedForeground = over(foreground, background)
        const fontSize = Number.parseFloat(style.fontSize)
        const fontWeight = Number.parseInt(style.fontWeight, 10) || 400
        const required = fontSize >= 24 || (fontSize >= 18.66 && fontWeight >= 700) ? 3 : 4.5
        const measured = Math.round(ratio(paintedForeground, background) * 100) / 100
        if (measured < required) {
          failures.push({ selector: describe(element), text: text.slice(0, 70), ratio: measured, required })
        }
      }
      return failures
    },
    [rootSelector, includeAriaHidden] as const,
  )
}

export function formatContrastFailures(failures: ContrastFailure[]): string[] {
  return failures.map(
    (failure) =>
      `${failure.ratio}:1 (needs ${failure.required}:1) ${failure.selector} — "${failure.text}"`,
  )
}