import type { Page } from '@playwright/test'

export interface NonTextFailure {
  kind: 'control-boundary' | 'generated-content'
  selector: string
  detail: string
  ratio: number
  required: number
}

export async function auditNonText(page: Page, rootSelector = 'body'): Promise<NonTextFailure[]> {
  return page.evaluate((within) => {
    type Rgba = { r: number; g: number; b: number; a: number }
    const root = document.querySelector(within) ?? document.body
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
      return normalized <= 0.04045 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4
    }
    const luminance = (color: Rgba): number =>
      0.2126 * channel(color.r) + 0.7152 * channel(color.g) + 0.0722 * channel(color.b)
    const ratio = (left: Rgba, right: Rgba): number => {
      const lighter = Math.max(luminance(left), luminance(right))
      const darker = Math.min(luminance(left), luminance(right))
      return (lighter + 0.05) / (darker + 0.05)
    }
    const white = { r: 255, g: 255, b: 255, a: 1 }
    const backgroundFor = (element: Element | null): Rgba => {
      let current = element
      let accumulated = { r: 0, g: 0, b: 0, a: 0 }
      while (current) {
        const color = parse(getComputedStyle(current).backgroundColor)
        if (color) accumulated = over(accumulated, color)
        if (accumulated.a >= 1) break
        current = current.parentElement
      }
      return over(accumulated, white)
    }
    const selector = (element: Element): string => {
      const id = element.id ? `#${element.id}` : ''
      const classes = [...element.classList].join('.')
      return `${element.tagName.toLowerCase()}${id}${classes ? `.${classes}` : ''}`
    }
    const failures: NonTextFailure[] = []
    const controls = root.querySelectorAll(
      'button,input:not([type="hidden"]),select,textarea,[role="button"],[role="switch"],[role="tab"],a[class*="button"],a[class*="btn"]',
    )
    for (const element of controls) {
      if (!(element as HTMLElement).checkVisibility?.() || (element as HTMLInputElement).disabled) continue
      const style = getComputedStyle(element)
      const rect = element.getBoundingClientRect()
      if (rect.width <= 0 || rect.height <= 0) continue
      const nativeInput = element instanceof HTMLInputElement && ['checkbox', 'radio', 'range'].includes(element.type)
      if (nativeInput && style.appearance !== 'none') continue

      const surround = backgroundFor(element.parentElement)
      const ownFill = parse(style.backgroundColor) ?? { r: 0, g: 0, b: 0, a: 0 }
      const fill = over(ownFill, surround)
      const paintedSides = (['top', 'right', 'bottom', 'left'] as const).filter((side) => {
        if (Number.parseFloat(style.getPropertyValue(`border-${side}-width`)) <= 0) return false
        if (style.getPropertyValue(`border-${side}-style`) === 'none') return false
        const color = parse(style.getPropertyValue(`border-${side}-color`))
        return Boolean(color && color.a > 0)
      })
      const hasOutline = Number.parseFloat(style.outlineWidth) > 0 && style.outlineStyle !== 'none'
      if (ownFill.a === 0 && paintedSides.length === 0 && !hasOutline) continue

      let best = ratio(fill, surround)
      let detail = `fill ${best.toFixed(2)}:1 vs surround`
      for (const side of paintedSides) {
        const borderColor = parse(style.getPropertyValue(`border-${side}-color`))!
        const measured = ratio(over(borderColor, fill), surround)
        if (measured > best) {
          best = measured
          detail = `border-${side} ${measured.toFixed(2)}:1 vs surround`
        }
      }
      const rounded = Math.round(best * 100) / 100
      if (rounded < 3) {
        failures.push({ kind: 'control-boundary', selector: selector(element), detail, ratio: rounded, required: 3 })
      }
    }

    for (const element of root.querySelectorAll('*')) {
      if (!(element as HTMLElement).checkVisibility?.()) continue
      for (const pseudo of ['::before', '::after'] as const) {
        const style = getComputedStyle(element, pseudo)
        const content = style.content.trim()
        if (['none', 'normal', '""', "''"].includes(content) || content.startsWith('url(')) continue
        const ink = parse(style.color)
        if (!ink || ink.a === 0) continue
        const background = backgroundFor(element)
        const fontSize = Number.parseFloat(style.fontSize)
        const fontWeight = Number.parseInt(style.fontWeight, 10) || 400
        const required = fontSize >= 24 || (fontSize >= 18.66 && fontWeight >= 700) ? 3 : 4.5
        const measured = Math.round(ratio(over(ink, background), background) * 100) / 100
        if (measured < required) {
          failures.push({ kind: 'generated-content', selector: `${selector(element)}${pseudo}`, detail: `content ${content}`, ratio: measured, required })
        }
      }
    }
    return failures
  }, rootSelector)
}